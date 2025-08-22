//go:build linux

package linux

import (
	"context"

	"github.com/Velocidex/ordereddict"
	"github.com/coreos/go-systemd/v22/dbus"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type SystemctlPluginArgs struct {
	Command    string   `vfilter:"required,field=command,doc=command to run"`
	Unit       string   `vfilter:"optional,field=unit,doc=unit to show"`
	Properties []string `vfilter:"optional,field=properties,doc=Properties to show"`
}

type SystemctlPlugin struct{}

func (s SystemctlPlugin) Info(scope vfilter.Scope, typeMap *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "systemctl",
		Doc:      "Get information about systemd services via dbus.",
		ArgType:  typeMap.AddType(scope, &SystemctlPluginArgs{}),
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

func (s SystemctlPlugin) Call(
	ctx context.Context, scope vfilter.Scope, args *ordereddict.Dict,
) <-chan vfilter.Row {
	outputCh := make(chan vfilter.Row)

	go func() {
		defer close(outputCh)

		err := vql.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("systemctl plugin: checking access: %s", err)
			return
		}

		arg := SystemctlPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)
		if err != nil {
			scope.Log("systemctl plugin: extracting args: %s", err)
			return
		}

		switch arg.Command {
		case "show":
			if arg.Unit == "" {
				scope.Log("systemctl plugin: unit required for command show")
				return
			}
			err := showProperties(ctx, scope, arg, outputCh)
			if err != nil {
				scope.Log("systemctl plugin: error showing properties: %v", err)
				return
			}
		default:
			scope.Log("systemctl plugin: invalid command: %s", arg.Command)
		}
	}()

	return outputCh
}

func showProperties(ctx context.Context, scope vfilter.Scope,
	arg SystemctlPluginArgs, outputCh chan vfilter.Row,
) error {
	conn, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	props, err := conn.GetUnitPropertiesContext(ctx, arg.Unit)
	if err != nil {
		return err
	}
	typeProps, err := conn.GetUnitTypePropertiesContext(ctx, arg.Unit, "Service")
	if err != nil {
		return err
	}

	row := ordereddict.NewDict()
	for _, p := range arg.Properties {
		if v, ok := props[p]; ok {
			row.Set(p, v)
			continue
		}
		if v, ok := typeProps[p]; ok {
			row.Set(p, v)
		}
	}
	outputCh <- row
	return nil
}

func init() {
	vql.RegisterPlugin(&SystemctlPlugin{})
}
