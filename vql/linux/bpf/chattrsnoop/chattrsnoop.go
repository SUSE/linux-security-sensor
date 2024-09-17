//go:build linux

package bpf

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"

	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
)

type ChattrsnoopPlugin struct{}

func (self ChattrsnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "chattrsnoop",
		Doc:      "Shows when a file has the IMMUTABLE flag changed",
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

type Event struct {
	Timestamp time.Time
	Path      string
	Dir       bool
	Action    string
}

func parseData(data []byte) (Event, error) {
	event := Event{
		Timestamp: time.Now(),
	}

	if len(data) < 1 {
		return event, errors.New("data empty")
	}

	event.Path = strings.Trim(string(data[1:]), "\x00")

	stat, err := os.Stat(event.Path)
	if err != nil {
		return event, err
	}
	event.Dir = stat.IsDir()

	if data[0] == 0 {
		event.Action = "CLEAR"
	} else {
		event.Action = "SET"
	}

	return event, nil
}

func (self ChattrsnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("chattrsnoop: %s", err)
			return
		}

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("chattrsnoop: unable to get config")
			return
		}
		config_obj := &config_proto.Config{Client: client_config_obj}
		logger := logging.GetLogger(config_obj, &logging.ClientComponent)

		bpfModule, err := initBpf(logger)
		if err != nil {
			scope.Log("chattrsnoop: Error initialising bpf: %s", err)
			return
		}

		defer bpfModule.Close()

		eventsChan := make(chan []byte)
		lostChan := make(chan uint64)

		perfBuffer, err := bpfModule.InitPerfBuf("events", eventsChan, lostChan, 128)
		if err != nil {
			scope.Log("chattrsnoop: Error opening bpf communication channel: %s", err)
			return
		}

		perfBuffer.Poll(300)

		for data := range eventsChan {
			event, err := parseData(data)
			if err != nil {
				scope.Log("chattrsnoop: parsing event: %v", err)
			}
			output_chan <- event
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&ChattrsnoopPlugin{})
}
