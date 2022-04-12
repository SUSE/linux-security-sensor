// +build linux

package bpf

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"

	"www.velocidex.com/golang/velociraptor/acls"
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

func calcSha256(f *os.File) string {
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal("h256: ", err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

type Event struct {
	Timestamp string
	Path      string
	Dir       bool
	Sha256sum string
	Action    string
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

		bpfModule, err := initBpf()
		if err != nil {
			scope.Log("chattrsnoop: Error initialising bpf")
			return
		}

		defer bpfModule.Close()

		eventsChan := make(chan []byte)
		lostChan := make(chan uint64)

		perfBuffer, err := bpfModule.InitPerfBuf("events", eventsChan, lostChan, 128)
		if err != nil {
			scope.Log("chattrsnoop: Error opening bpf communication channel")
			return
		}

		perfBuffer.Start()

		for data := range eventsChan {
			path := strings.Trim(string(data[1:]), "\x00")
			var hash string

			f, err := os.Open(path)
			if err != nil {
				scope.Log("chattrsnoop: Error opening: %s", path)
				continue
			}

			defer f.Close()
			mode, err := f.Stat()
			if err != nil {
				scope.Log("chattrsnoop: Error stating: %s", path)
			}

			if !mode.IsDir() {
				hash = calcSha256(f)
			}

			e := Event{
				Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"), Path: path,
				Dir: mode.IsDir(), Sha256sum: hash,
			}

			if data[0] == 0 {
				e.Action = "CLEAR"
			} else {
				e.Action = "SET"
			}

			output_chan <- e
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&ChattrsnoopPlugin{})
}
