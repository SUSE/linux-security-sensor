//go:build linux

package bpf

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
	"www.velocidex.com/golang/vfilter"
)

const (
	DNSSNOOP = "dnssnoop"
)

type DnssnoopPlugin struct{}

type DnsReply struct {
	Timestamp time.Time
	Type      string
	Question  string
	Answers   []string
}

type DnsKey struct {
	q    string
	Type string
}

func (self DnssnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "dnssnoop",
		Doc:      "Snoop dns replies",
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

func getKey(domainQuery string, dnsType layers.DNSType) DnsKey {
	var typeString string

	switch dnsType {
	case layers.DNSTypeA:
		typeString = "A"
	case layers.DNSTypeAAAA:
		typeString = "AAAA"
	case layers.DNSTypeMX:
		typeString = "MX"
	}

	return DnsKey{q: domainQuery, Type: typeString}
}

func processAnswers(answers []layers.DNSResourceRecord) map[DnsKey][]string {
	replies := make(map[DnsKey][]string)

	for _, answer := range answers {
		name := string(answer.Name)
		switch answer.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			key := getKey(name, answer.Type)

			if val, ok := replies[key]; ok {
				replies[key] = append(val, answer.IP.String())
			} else {
				replies[key] = []string{answer.IP.String()}
			}

		case layers.DNSTypeMX:
			key := getKey(name, answer.Type)

			if val, ok := replies[key]; ok {
				replies[key] = append(val, string(answer.MX.Name))
			} else {
				replies[key] = []string{string(answer.MX.Name)}
			}
		}
	}

	return replies
}

func isLocalPacket(packet gopacket.Packet) bool {
	switch ip := packet.NetworkLayer().(type) {
	case *layers.IPv4:
		if ip.SrcIP.IsLoopback() {
			return true
		}
	case *layers.IPv6:
		if ip.SrcIP.IsLoopback() {
			return true
		}
	}

	return false
}

func try_parse_packet(raw []byte) gopacket.Packet {
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		packet = gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
		if err = packet.ErrorLayer(); err != nil {
			packet = gopacket.NewPacket(raw, layers.LayerTypeIPv6, gopacket.Default)
			if err = packet.ErrorLayer(); err != nil {
				return nil
			}
		}
	}

	return packet
}

func (self DnssnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("dnssnoop: %s", err)
			return
		}

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("dnssnoop: unable to get config")
			return
		}
		config_obj := &config_proto.Config{Client: client_config_obj}
		logger := logging.GetLogger(config_obj, &logging.ClientComponent)

		subscriber := bpf.GetManager().Subscribe(DNSSNOOP, &publisher{logger: logger})
		defer bpf.GetManager().Unsubscribe(DNSSNOOP, subscriber)

		for {
			select {
			case <-ctx.Done():
				return

			case event := <-subscriber.EventCh:
				output_chan <- event

			case err := <-subscriber.ErrorCh:
				scope.Log("%v", err)
				return
			}
		}
	}()

	return output_chan
}

type publisher struct {
	wg     sync.WaitGroup
	cancel func()
	logger *logging.LogContext
}

func (p *publisher) Start() {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	bpfModuleLoadDoneCh := make(chan struct{})

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		bpfModule, sockFd, err := initBpf(p.logger)
		bpfModuleLoadDoneCh <- struct{}{}
		if err != nil {
			e := fmt.Errorf("dnssnoop: initBpf: %s", err)
			bpf.GetManager().PublishError(ctx, DNSSNOOP, e)
			return
		}

		defer bpfModule.Close()
		defer unix.Close(sockFd)

		err = syscall.SetNonblock(sockFd, true)
		if err != nil {
			e := fmt.Errorf("dnsnoop: SetNonBlock error: %s", err)
			bpf.GetManager().PublishError(ctx, DNSSNOOP, e)
			return
		}

		f := os.NewFile(uintptr(sockFd), "")
		if f == nil {
			e := fmt.Errorf("dnssnoop: error opening file from socket descriptor")
			bpf.GetManager().PublishError(ctx, DNSSNOOP, e)
			return
		}
		defer f.Close()

		data := make([]byte, 1500)
		for {
			err := f.SetReadDeadline(time.Now().Add(time.Second))
			if err != nil {
				e := fmt.Errorf("dnssnoop: SetReadDeadline error: %v", err)
				bpf.GetManager().PublishError(ctx, DNSSNOOP, e)
				return
			}

			_, err = f.Read(data)

			if ctx.Err() != nil {
				return
			}

			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				e := fmt.Errorf("dnssnoop: error reading from socket: %v", err)
				bpf.GetManager().PublishError(ctx, DNSSNOOP, e)
				return
			}

			packet := try_parse_packet(data)
			if packet == nil {
				continue
			}

			// skip duplicate replies from local resolver
			if isLocalPacket(packet) {
				continue
			}

			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)

				if dns.ANCount > 0 {
					replies := processAnswers(dns.Answers)
					for k, v := range replies {
						reply := DnsReply{time.Now(), k.Type, k.q, v}
						bpf.GetManager().PublishEvent(ctx, DNSSNOOP, reply)
					}
				}
			}
		}
	}()

	<-bpfModuleLoadDoneCh // wait until the BPF module is loaded
}

func (p *publisher) Stop() {
	p.cancel()
	p.wg.Wait()
}

func init() {
	vql_subsystem.RegisterPlugin(&DnssnoopPlugin{})
}
