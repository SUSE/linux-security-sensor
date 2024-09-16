//go:build linux

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
)

type TcpsnoopPlugin struct{}

func (self TcpsnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "tcpsnoop",
		Doc:      "Report incoming/outgoing tcp connections",
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

type Event struct {
	Timestamp  time.Time
	RemoteAddr string
	LocalAddr  string
	Task       string
	Af         string // AF_INET or AF_INET6
	Pid        uint32
	Uid        uint32
	RemotePort uint16
	LocalPort  uint16
	Dir        string
}

func parseData(data []byte) (Event, error) {
	var event TcpsnoopEvent

	// Parses raw event from the ebpf map
	nativeEndian := utils.NativeEndian()
	err := binary.Read(bytes.NewBuffer(data), nativeEndian, &event)
	if err != nil {
		return Event{}, err
	}

	// Now we make into a more userfriendly struct for sending to VRR
	event2 := Event{
		Timestamp:  time.Now(),
		LocalPort:  event.Lport,
		RemotePort: event.Rport,
		Uid:        event.Uid,
		Pid:        event.Pid,
		Task:       string(bytes.Trim(event.Task[:], "\000")),
	}

	if event.Af == AF_INET {
		event2.Af = "IPv4"
		event2.RemoteAddr = net.IP.String(event.Raddr[:4])
		event2.LocalAddr = net.IP.String(event.Laddr[:4])
	} else {
		event2.RemoteAddr = net.IP.String(event.Raddr[:])
		event2.LocalAddr = net.IP.String(event.Laddr[:])
		event2.Af = "IPv6"
	}

	if event.Dir == OUT_CON {
		event2.Dir = "OUTGOING"
	} else {
		event2.Dir = "INCOMING"
	}

	return event2, nil
}

func (self TcpsnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("tcpsnoop: %s", err)
			return
		}

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("tcpsnoop: unable to get config")
			return
		}
		config_obj := &config_proto.Config{Client: client_config_obj}
		logger := logging.GetLogger(config_obj, &logging.ClientComponent)

		// Load bpf program and attach to tracepoints
		bpf, err := initBpf(logger)
		if err != nil {
			scope.Log("tcpsnoop: initBpf: %s", err)
			return
		}
		defer bpf.Close()

		eventsChan := make(chan []byte)
		lostChan := make(chan uint64)

		perfBuffer, err := bpf.InitPerfBuf("events", eventsChan, lostChan, 128)
		if err != nil {
			scope.Log("tcpsnoop: InitPerfBuf: %s", err)
			return
		}

		perfBuffer.Poll(300)

		for data := range eventsChan {
			event, err := parseData(data)
			if err != nil {
				scope.Log("tcpsnoop: failed to decode received data: %s", err)
				continue
			}

			output_chan <- event
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&TcpsnoopPlugin{})
}
