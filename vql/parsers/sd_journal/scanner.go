
package sd_journal

import (
	"context"
	"fmt"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
        "www.velocidex.com/golang/vfilter/arg_parser"
        "github.com/coreos/go-systemd/v22/sdjournal"

)
type ScannerPluginArgs struct {
}


type ScannerPlugin struct {
	journal		*sdjournal.Journal
}

func (self *ScannerPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:	"scan_journal",
		Doc:	"Scan the systemd journal for events",
		ArgType: type_map.AddType(scope, &ScannerPluginArgs{}),
	}
}

func (self *ScannerPlugin) openJournal() error {
	jflags := sdjournal.SD_JOURNAL_LOCAL_ONLY
	jflags |= sdjournal.SD_JOURNAL_SYSTEM
	journal, err := sdjournal.NewJournalWithFlags(jflags)
	if err != nil {
		return fmt.Errorf("Failed to open journal: %v", err)
	}

	if journal == nil {
		return fmt.Errorf("BUG: NewJournalWithFlags did not return error but journal is nil")
	}

	self.journal = journal
	return nil
}

func (self *ScannerPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <- chan vfilter.Row {

	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)

		scope.Log("Setting up to scan journal")

		arg := &ScannerPluginArgs{}
		err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("Cannot start Journal Scanner Plugin: %v", err)
			return
		}

		err = self.openJournal()
		if err != nil {
			scope.Log("Cannot start Journal Scanner Plugin: %v", err)
			return
		}

		self.scanJournal(ctx, scope, arg, output_chan)
	}()

	return output_chan
}

func prepareJournalEntry(entry *sdjournal.JournalEntry) *ordereddict.Dict {
	d := ordereddict.NewDict()
	for name, value := range(entry.Fields) {
		d.Set(name, value)
	}

	d.Set("REALTIME_TIMESTAMP", entry.RealtimeTimestamp)
	d.Set("MONOTONIC_TIMESTAMP", entry.MonotonicTimestamp)

	return d
}

func (self *ScannerPlugin) scanJournal(ctx context.Context, scope vfilter.Scope,
				      arg *ScannerPluginArgs,
				      output_chan chan <- vfilter.Row) {
	if self.journal == nil {
		scope.Log("BUG: Journal is not open")
		return
	}
	err := self.journal.SeekHead()
	if err != nil {
		scope.Log("Failed to seek to head of journal: %v", err)
		return
	}

	scope.Log("Scanning journal...")

	count := 0
	var cur uint64 = 0

	self.journal.Wait(0)

	once := true

	for cur, err = self.journal.Next(); err == nil && cur > 0; cur, err = self.journal.Next() {
		entry, err := self.journal.GetEntry()
		if err != nil  {
			scope.Log("Failed to read entry: %v", err)
			return
		}

		d := prepareJournalEntry(entry)

		if once {
			scope.Log("Sample entry: %v", d)
			once = false
		}
		output_chan <- d
		count += 1
	}

	if err != nil {
		scope.Log("Failed to increment journal: %v", err)
		return
	}

	scope.Log("Output %v entries", count)
}

func init() {
	vql_subsystem.RegisterPlugin(&_WatchJournalPlugin{})
	vql_subsystem.RegisterPlugin(&ScannerPlugin{})
}
