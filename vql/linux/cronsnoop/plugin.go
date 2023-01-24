//go:build linux
// +build linux

package linux

import (
	"context"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/logging"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type CronsnoopArgs struct {
	SpoolPath   string   `vfilter:"required,field=spool_dir,doc=Spool directory where user cron files are located"`
	SystemPaths []string `vfilter:"required,field=system_dirs,doc=Directories to be watched where system cron files are located"`
}

type CronsnoopPlugin struct{}

func (self CronsnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "cronsnoop",
		Doc:  "Snoops changes to cron files",
	}
}

func (self CronsnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {

	output_chan := make(chan vfilter.Row)
	arg := &CronsnoopArgs{}
	err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)

	if err != nil {
		scope.Log("cronsnoop: %s", err.Error())
	}

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("cronsnoop: %s", err)
			return
		}

		config_obj, ok := vql_subsystem.GetServerConfig(scope)
		if !ok {
			scope.Log("cronsnoop: Couldn't obtain server config")
			return

		}
		logger := logging.GetLogger(config_obj, &logging.ClientComponent)

		// Make the chan large enough so that cron snooper doesn't block, waiting
		// for the channel too be consumed
		eventChan := make(chan CronEvent, 1000)
		snooper, err := NewCronSnooperWithChan(arg.SpoolPath, arg.SystemPaths, eventChan)
		defer close(eventChan)

		if err != nil {
			scope.Log("cronsnoop: Error creating snooper instance", err)
			return
		}

		snooper.SetLogger(logger)

		defer snooper.Close()
		err = snooper.WatchCrons()
		if err != nil {
			scope.Log("cronsnoop: Error starting cron watchers: %v", err)
			return
		}

		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					scope.Log("cronsnoop: Couldn't receive from event chan, dying")
					return
				}

				output_chan <- event

			case <-ctx.Done():
				return
			}
		}

	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&CronsnoopPlugin{})
}
