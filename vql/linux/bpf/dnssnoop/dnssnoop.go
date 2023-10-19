// +build linux

package bpf

import (
	"context"
	_ "embed"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Velocidex/ordereddict"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
)

type DnssnoopPlugin struct{}

type DnsReply struct {
	Timestamp string
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

func processAnswers(answers []layers.DNSResourceRecord, c chan vfilter.Row) {
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

	for k, v := range replies {
		c <- DnsReply{time.Now().UTC().Format("2006-01-02 15:04:05"), k.Type, k.q, v}
	}
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

		// Load bpf program and attach to tracepoints
		bpf, sockFd, err := initBpf()
		if err != nil {
			scope.Log("dnssnoop: %s", err)
			return
		}

		defer bpf.Close()
		defer unix.Close(sockFd)

		f := os.NewFile(uintptr(sockFd), "")
		if f == nil {
			scope.Log("Error opening file to socket descriptor")
			return
		}
		defer f.Close()

		received_data := make([]byte, 1500)

		for {
			_, err := f.Read(received_data)
			if err != nil {
				scope.Log("Error reading from socket: %v", err)
				return
			}

			packet := try_parse_packet(received_data)
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
					processAnswers(dns.Answers, output_chan)
				}
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&DnssnoopPlugin{})
}
