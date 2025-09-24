package server

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/leodido/go-syslog/rfc5424"
	"golang.org/x/time/rate"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/directory"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

const pluginName = "rsyslog_upload"

type rsyslogUploadPluginArgs struct {
	Query      vfilter.StoredQuery `vfilter:"required,field=query,doc=Source for rows to upload."`
	UnixDomain string              `vfilter:"required,field=unix_domain,doc=path to unix domain socket rsyslog listens on"`
	Threads    int                 `vfilter:"optional,field=threads,doc=How many threads to use to send events."`
}

type rsyslogUploadPlugin struct{}

func (r rsyslogUploadPlugin) Info(
	scope vfilter.Scope, typeMap *vfilter.TypeMap,
) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     pluginName,
		Doc:      "Upload rows to rsyslog",
		ArgType:  typeMap.AddType(scope, &rsyslogUploadPluginArgs{}),
		Metadata: vql.VQLMetadata().Permissions(acls.COLLECT_SERVER).Build(),
	}
}

func (r rsyslogUploadPlugin) Call(
	ctx context.Context, scope vfilter.Scope, args *ordereddict.Dict,
) <-chan vfilter.Row {
	// this plugin does not send anything to its output channel
	outputCh := make(chan vfilter.Row)

	go func() {
		defer close(outputCh)
		defer vql.RegisterMonitor(ctx, "rsyslog_upload", args)()
		defer utils.RecoverVQL(scope)

		err := vql.CheckAccess(scope, acls.COLLECT_SERVER)
		if err != nil {
			scope.Log("%s: check access failed: %v", pluginName, err)
			return
		}

		arg := rsyslogUploadPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, &arg)
		if err != nil {
			scope.Log("%s: parsing args: %v", pluginName, err)
			return
		}
		if arg.UnixDomain == "" {
			scope.Log("%s: parameter UnixDomain must be set", pluginName)
			return
		}
		if arg.Threads == 0 {
			arg.Threads = 1
		}

		configObj, ok := vql.GetServerConfig(scope)
		if !ok {
			scope.Log("%s: could not get config from scope", pluginName)
			return
		}

		options := api.QueueOptions{
			DisableFileBuffering: false,
			FileBufferLeaseSize:  100,
			OwnerName:            pluginName,
		}

		listenerCtx, cancelListener := context.WithCancel(context.Background())
		defer cancelListener()

		listener, err := directory.NewListener(configObj, listenerCtx, pluginName, options)
		if err != nil {
			scope.Log("%s: could not create listener: %v", pluginName, err)
			return
		}

		scope.Log("%s: starting %d worker threads", pluginName, arg.Threads)
		wg := sync.WaitGroup{}
		for i := 0; i < arg.Threads; i++ {
			wg.Add(1)
			go rsyslogSender(ctx, &wg, arg.UnixDomain, scope, listener.Output())
		}

		rowCh := arg.Query.Eval(ctx, scope)

		quitLoop := false
		for !quitLoop {
			select {
			case <-ctx.Done():
				listener.Close()
				quitLoop = true
			case row, ok := <-rowCh:
				if !ok {
					continue
				}
				listener.Send(vfilter.RowToDict(ctx, scope, row))
			}
		}

		// the workers will return when they detect that
		// the listener had closed its output channel
		wg.Wait()
	}()
	return outputCh
}

func rsyslogSender(
	ctx context.Context, wg *sync.WaitGroup, address string,
	scope vfilter.Scope, rowCh <-chan *ordereddict.Dict,
) {
	defer func() {
		scope.Log("%s: worker done", pluginName)
		wg.Done()
	}()

	scope.Log("%s: worker started", pluginName)
	var (
		pid        = strconv.Itoa(os.Getpid())
		conn       net.Conn
		message    string
		rrDialLog  = rate.Sometimes{Interval: time.Minute}
		rrWriteLog = rate.Sometimes{Interval: time.Minute}
	)
	for {
		if conn == nil {
			var err error
			conn, err = net.DialTimeout("unixgram", address, time.Second)
			if err != nil {
				rrDialLog.Do(func() { scope.Log("%s: dialing: %v", pluginName, err) })
				utils.SleepWithCtx(ctx, time.Second)
				if ctx.Err() != nil {
					// avoid spinning here if rsyslogd is not
					// listening when the plugin is shutting down.
					return
				}
				conn = nil // probably not needed, but no harm.
				continue   // retry dial
			}
			scope.Log("%s: worker connected!", pluginName)
		}
		if message == "" {
			row, ok := <-rowCh
			if !ok {
				// the listener closed its channel
				return
			}
			var err error
			message, err = rowToRsyslogString(row, pid)
			if err != nil {
				scope.Log("%s: creating rsyslog message: %v", pluginName, err)
				return
			}
		}
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		_, err := io.WriteString(conn, message)
		if err != nil {
			rrWriteLog.Do(func() { scope.Log("%s: writing to conn: %v", pluginName, err) })
			conn.Close()
			conn = nil // conn is an interface!
			continue   // Retry sending the same message on the next iteration.
		}

		// the message was sent successfully.
		message = ""
	}
}

func rowToRsyslogString(row *ordereddict.Dict, pid string) (string, error) {
	message := rfc5424.SyslogMessage{}
	message.SetPriority(0)
	message.SetVersion(1)
	message.SetAppname("velociraptor")
	message.SetProcID(pid)
	message.SetMessage(row.String()) // json

	return message.String()
}

func init() {
	vql.RegisterPlugin(&rsyslogUploadPlugin{})
}
