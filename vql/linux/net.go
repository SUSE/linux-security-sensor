// +build linux

package linux

import (
	"context"
	"net"

	"github.com/Velocidex/ordereddict"

	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/vfilter"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"



)

type LinuxNetPlugin struct {
}

// Needed values:
// IPAddresses (with prefix)
// MACAddress
// On Windows, we have the following as well.  These are unimplemented on Linux ATM.
// Subnets
// DefaultGateway
// DNSServer
// DNSServerSearchOrder

func (self LinuxNetPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "linux_net",
		Doc:  "Collect network configuration on Linux clients",
	}
}

func (self LinuxNetPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("linux_net: %s", err)
			return
		}

		interfaces, err := net.Interfaces()
		if err != nil {
			scope.Log("linux_net: Failed to get interfaces: %s", err)
			return
		}


		for _, iface := range interfaces {
			if iface.Flags & net.FlagLoopback == net.FlagLoopback {
				continue
			}
			row := ordereddict.NewDict().
				Set("Name", iface.Name).
				Set("MACAddress", iface.HardwareAddr.String()).
				Set("MTU", iface.MTU)

			ptp := "N"
			if iface.Flags & net.FlagPointToPoint == net.FlagPointToPoint {
				ptp = "Y"
			}
			row.Set("PointToPoint", ptp)

			up := "N"
			if iface.Flags & net.FlagUp == net.FlagUp {
				up = "Y"
			}
			row.Set("Up", up)

			addrs, err := iface.Addrs()
			if err != nil {
				scope.Log("linux_net: Failed to get addresses for interface %s: %s", iface.Name, err)
				continue
			}

			addrList := []string{}
			for _, addr := range addrs {
				addrList = append(addrList, addr.String())
			}

			row.Set("IPAddresses", addrList)
			output_chan <- row
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&LinuxNetPlugin{})
}
