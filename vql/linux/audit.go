// +build linux

package linux

import (
	"context"
	"fmt"
	"time"
        "strings"
        "sync"

	"github.com/Velocidex/ordereddict"
	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/aucoalesce"
	"github.com/elastic/go-libaudit/auparse"
        "github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"www.velocidex.com/golang/velociraptor/acls"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
        "www.velocidex.com/golang/vfilter/arg_parser"
)

var auditrules []string
var m sync.Mutex

type streamHandler struct {
	scope       vfilter.Scope
	output_chan chan vfilter.Row
}

func (self *streamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	self.outputMultipleMessages(msgs)
}

func (self *streamHandler) EventsLost(count int) {
	self.scope.Log("Detected the loss of %v sequences.", count)
}

func (self *streamHandler) outputMultipleMessages(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		return
	}
	self.output_chan <- event
}

type _AuditPluginArgs struct {
        Rules      []string            `vfilter:"optional,field=rules,doc=List of rules"`
}

type AuditPlugin struct{}


func (self AuditPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "audit",
		Doc:  "Register as an audit daemon in the kernel.",
	}
}

func addRules(c *libaudit.AuditClient, rulelst []string, s vfilter.Scope, rf bool) (error) {
       for _, line := range rulelst {
              r, err := flags.Parse(line)
              if err != nil {
                     s.Log("Error parsing Rule %v: %s", err)
                     return fmt.Errorf("Error while adding rules: %w", err)
               }
               data, err := rule.Build(r)
               if err != nil {
                      s.Log("Error Building Rule: %s", err)
                      return fmt.Errorf("Error while adding rules: %w", err)
               }
               //defer c.GetRules()
               //defer deleteRules(c)
               if err := c.AddRule([]byte(data)); err != nil {
                       if strings.Contains(err.Error(), "rule exists"){
                              continue
                       } else {
                              s.Log("Error while adding Rule %s: %s", line,err)
                              return fmt.Errorf("error adding audit rule: %w", err)
                       }

               }
               if rf == false { 
                       auditrules = append(auditrules, line)
               }
               s.Log("Added Rule %s", line)
       }
       return nil
}

func deleteRules(client *libaudit.AuditClient) {
	if _, err := client.DeleteRules(); err != nil {
	}
}

func (self AuditPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

        //var rs_flag bool = false
	go func() {
                var rs_flag bool = false
		defer close(output_chan)

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("audit: %s", err)
			return
		}

                arg := _AuditPluginArgs{}
                err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)

		client, err := libaudit.NewMulticastAuditClient(nil)
		if err != nil {
			scope.Log("audit: %v", err)
			return
		}
		defer client.Close()

		reassembler, err := libaudit.NewReassembler(5, 2*time.Second,
			&streamHandler{scope, output_chan})
		if err != nil {
			scope.Log("audit: %v", err)
			return
		}
		defer reassembler.Close()

                //defer deleteRules(client)
                defer client.GetRules()
                err = addRules(client, arg.Rules, scope, rs_flag)
                if err != nil {
                        scope.Log("Error: %s", err)
                }

		// Start goroutine to periodically purge timed-out events.
		go func() {
			t := time.NewTicker(500 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return

				case <-t.C:
					if reassembler.Maintain() != nil {
						return
					}
				}
			}
		}()

		for {
			rawEvent, err := client.Receive(false)
			if err != nil {
				scope.Log("receive failed: %s", err)
				continue
			}

			// Messages from 1300-2999 are valid audit messages.
			if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
				rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
				continue
			}

			line := fmt.Sprintf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
			auditMsg, err := auparse.ParseLogLine(line)
                        if err == nil {
                                reassembler.PushMessage(auditMsg)
                                mapstr := auditMsg.ToMapStr()
                                ptitle := fmt.Sprint(mapstr["proctitle"])
                                if (strings.Contains(ptitle, "restart auditd") || strings.Contains(ptitle, "auditctl -D")) {
                                       //scope.Log("Inside restarting auditd")
                                       //scope.Log("MapStr %v", mapstr["proctitle"])
                                       m.Lock()
                                       rs_flag = true
                                       defer client.GetRules()
                                       scope.Log("Audit rules to add %v", len(auditrules))
                                       err = addRules(client, auditrules, scope, rs_flag)
                                       if err != nil {
                                              scope.Log("Error: %s", err)
                                       }
                                       m.Unlock()
                                }
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&AuditPlugin{})
}
