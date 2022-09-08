// +build linux
 
package linux

import (
	"context"
	"syscall"

	"github.com/Velocidex/ordereddict"

	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/vfilter"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
)

type LinuxInfoPlugin struct {
}

// Needed values:
// TotalPhysicalMemory
// TotalFreeMemory
func (self LinuxInfoPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "linux_info",
		Doc:  "Collect system information on Linux clients",
	}
}

func (self LinuxInfoPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("linux_info: %s", err)
			return
		}

		in := &syscall.Sysinfo_t{}
		err = syscall.Sysinfo(in)
		if err != nil {
			scope.Log("linux_info: sysinfo() failed: %s", err)
			return
		}

		row := ordereddict.NewDict().
			Set("TotalPhysicalMemory", uint64(in.Totalram) * uint64(in.Unit)).
			Set("TotalFreeMemory", uint64(in.Freeram) * uint64(in.Unit)).
			Set("TotalSharedMemory", uint64(in.Sharedram) * uint64(in.Unit)).
			Set("TotalSwap", uint64(in.Totalswap) * uint64(in.Unit)).
			Set("FreeSwap", uint64(in.Freeswap) * uint64(in.Unit))
			output_chan <- row
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&LinuxInfoPlugin{})
}
