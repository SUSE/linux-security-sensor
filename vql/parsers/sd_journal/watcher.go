package sd_journal

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
        "www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
        "www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/utils"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
        "www.velocidex.com/golang/vfilter/arg_parser"
        "github.com/coreos/go-systemd/v22/sdjournal"

)

const (
	FREQUENCY   = 3 * time.Second
	BUFFER_SIZE = 16 * 1024
)

var (
	mu             sync.Mutex
	gJournalService *JournalWatcherService
)

func GlobalJournalService(config_obj *config_proto.Config) (*JournalWatcherService, error) {
	mu.Lock()
	defer mu.Unlock()

	var err error = nil

	if gJournalService == nil {
		gJournalService, err = NewJournalWatcherService(config_obj)
		if err != nil {
			return nil, err
		}
	}

	return gJournalService, nil
}

// This service watches the systemd journal and multiplexes events to multiple readers.
type JournalWatcherService struct {
	mu sync.Mutex

	config_obj      *config_proto.Config
	listeners       []*Handle
	nListeners	int
	journal		*sdjournal.Journal
}

func NewJournalWatcherService(config_obj *config_proto.Config) (*JournalWatcherService, error) {
	jflags := sdjournal.SD_JOURNAL_LOCAL_ONLY
	jflags |= sdjournal.SD_JOURNAL_SYSTEM
	journal, err := sdjournal.NewJournalWithFlags(jflags)
	if err != nil {
		return nil, errors.New("Failed to open journal")
	}

	return &JournalWatcherService{
		config_obj:    config_obj,
		listeners: make([]*Handle, 0, 1),
		journal:       journal,
	}, nil
}

func (self *JournalWatcherService) Register(
	ctx context.Context,
	scope vfilter.Scope,
	output_chan chan vfilter.Row) func() {

	self.mu.Lock()
	defer self.mu.Unlock()

	subctx, cancel := context.WithCancel(ctx)

	handle := &Handle{
		ctx:         subctx,
		output_chan: output_chan,
		scope:       scope}

	self.listeners = append(self.listeners, handle)
	self.nListeners += 1
	if self.nListeners == 1 {
		go self.StartMonitoring()
	}

	scope.Log("Registered listener for systemd journal")

	return cancel
}

// Monitor the journal for new events and emit them to all interested
// listeners. If no listeners exist we terminate.
func (self *JournalWatcherService) StartMonitoring() {

	defer utils.CheckForPanic("StartMonitoring")

	scope := vql_subsystem.MakeScope()
	defer scope.Close()

	defer self.journal.Close()

	err := self.journal.SeekTail()
	if err != nil {
		scope.Log("Failed to seek tail of journal: %v", err)
		return
	}

	for {
		status := self.journal.Wait(100 * time.Millisecond)

		switch status {
		case sdjournal.SD_JOURNAL_NOP:
			continue
		case sdjournal.SD_JOURNAL_APPEND, sdjournal.SD_JOURNAL_INVALIDATE:
		default:
			if status < 0 {
				scope.Log("Recieved error %v while waiting on journal", status)
				return
			}
			scope.Log("Received unknown event %v while waiting on journal", status)
		}

		listen, err := self.monitorOnce()
		if listen == false || err != nil {
			if err != nil {
				scope.Log("Aborting journal watcher: %v", err)
			}
			return
		}
	}
}

func (self *JournalWatcherService) monitorOnce() (bool, error) {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.nListeners == 0 {
		return false, nil
	}

	var err error
	var cur uint64 = 0

	for cur, err = self.journal.Next(); err == nil && cur > 0; cur, err = self.journal.Next() {
		entry, err := self.journal.GetEntry()
		if err != nil {
			logger := logging.GetLogger(self.config_obj, &logging.ClientComponent)
			logger.Warning("Failed to read log entry: %v", err)
			return true, err
		}

		self.distributeEntry(entry)
	}

	if err == io.EOF {
		err = nil
	}

	return self.nListeners > 0, err
}

func (self *JournalWatcherService) distributeEntry(entry *sdjournal.JournalEntry) {
	// Common case will just recreate the slice
	new_handles := make([]*Handle, 0, len(self.listeners))

	d := prepareJournalEntry(entry)

	for _, handle := range self.listeners {
		select {
		case <-handle.ctx.Done():
			// If context is done, drop the event.
			self.nListeners -= 1

		case handle.output_chan <- d:
			logger := logging.GetLogger(self.config_obj, &logging.ClientComponent)
			logger.Info("Output entry: %v", d)
			new_handles = append(new_handles, handle)
		}
	}
	self.listeners = new_handles
}

// A handle is given for each interested party. We write the event on
// to the output_chan unless the context is done. When all interested
// parties are done we may destroy the monitoring go routine and remove
// the registration.
type Handle struct {
	ctx         context.Context
	output_chan chan vfilter.Row
	scope       vfilter.Scope
}

type _WatchJournalPlugin struct{
}

type _WatchJournalPluginArgs struct {
}


func (self _WatchJournalPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:	"watch_journal",
		Doc:	"Watch the systemd journal for events",
		ArgType: type_map.AddType(scope, &_WatchJournalPluginArgs{}),
	}
}

func (self _WatchJournalPlugin) Call(
	ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) <- chan vfilter.Row {

	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		arg := &_WatchJournalPluginArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("watch_journal: %v", err)
			return
		}

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("watch_journal: unable to get config from scope %v", scope)
			return
		}

		config_obj := &config_proto.Config{Client: client_config_obj}

		event_channel := make(chan vfilter.Row)

		journalService, err := GlobalJournalService(config_obj)
		if err != nil {
			scope.Log("watch_journal: Could not start journal service: %v", err)
		}

		scope.Log("Registered watcher for systemd journal")
		cancel := journalService.Register(ctx, scope, event_channel)
		defer cancel()

		for {
			select {
			case <- ctx.Done():
				return
			case event := <-event_channel:
				select {
				case <-ctx.Done():
						return
				case output_chan <- event:
				}
			}
		}
	}()

	return output_chan
}
