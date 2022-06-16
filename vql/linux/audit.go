package linux

import (
	"context"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	audit "www.velocidex.com/golang/velociraptor/vql/linux/audit"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

type _AuditPluginArgs struct {
	Rules []string `vfilter:"optional,field=rules,doc=List of rules"`
}

type AuditPlugin struct{}

func (self AuditPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "audit",
		Doc:      "Register as an audit daemon in the kernel.",
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

func (self AuditPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("audit: %s", err)
			return
		}

		arg := _AuditPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)
		if err != nil {
			scope.Log("audit: %s", err)
			return
		}

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("audit: unable to get config from scope %v", scope)
			return
		}

		config_obj := config_proto.Config{Client: client_config_obj}
		auditService, err := audit.GetAuditService(&config_obj)
		if err != nil {
			scope.Log("audit: Could not get audit service: %v", err)
			return
		}

		subscriber, err := auditService.Subscribe(arg.Rules)
		if err != nil {
			scope.Log("audit: Could not subscribe to audit service: %v", err)
			return
		}

		defer scope.Log("audit: Unsubscribed to audit service")
		defer auditService.Unsubscribe(subscriber)
		scope.Log("audit: Subscribed to audit service")

		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-subscriber.LogEvents():
				if !ok {
					scope.Log("audit: audit service disconnected unexpectedly")
					return
				}
				scope.Log(msg)
			case event, ok := <-subscriber.Events():
				if !ok {
					scope.Log("audit: audit service disconnected unexpectedly")
					return
				}

				// Convert the events to dicts so they can be accessed easier.
				dict := vfilter.RowToDict(ctx, scope, event)
				dict.SetCaseInsensitive()
				output_chan <- dict
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&AuditPlugin{})
}
