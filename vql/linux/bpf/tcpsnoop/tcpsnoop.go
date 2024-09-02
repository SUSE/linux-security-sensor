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
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"local_address"`
	LocalAddr  string `json:"remote_address"`
	Task       string `json:"task"`
	Af         string `json:"protocol"` // AF_INET or AF_INET6
	Pid        uint32 `json:"pid"`
	Uid        uint32 `json:"uid"`
	RemotePort uint16 `json:"remote_port"`
	LocalPort  uint16 `json:"local_port"`
	Dir        string `json:"con_dir"`
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
			scope.Log("tcpsnoop: %s", err)
			return
		}
		defer bpf.Close()

		eventsChan := make(chan []byte)
		lostChan := make(chan uint64)

		perfBuffer, err := bpf.InitPerfBuf("events", eventsChan, lostChan, 128)
		if err != nil {
			scope.Log("tcpsnoop: %s", err)
			return
		}

		perfBuffer.Start()
		nativeEndian := utils.NativeEndian()

		for data := range eventsChan {
			var event TcpsnoopEvent

			// Parses raw event from the ebpf map
			err := binary.Read(bytes.NewBuffer(data), nativeEndian, &event)

			// Now we make into a more userfriendly struct for sending to VRR
			event2 := Event{
				Timestamp:  time.Now().UTC().Format("2006-01-02 15:04:05"),
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

			if err != nil {
				scope.Log("failed to decode received data: %s\n", err)
				continue
			}

			// print the tcp event to VRR's channel
			output_chan <- event2
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&TcpsnoopPlugin{})
}
