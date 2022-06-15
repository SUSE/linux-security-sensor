// +build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"time"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/Velocidex/ordereddict"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	auditrule "github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

var (
	gLock sync.Mutex
	gService *AuditWatcherService
	// Timeout for batching audit configuration events
	gBatchTimeout = 1000 * time.Millisecond
	debugGoRoutines = false
)

var gBannedRules = []string{
	"-d task,never",
}

type AuditWatcherRule struct {
	wfRule	auditrule.WireFormat
	rule	string
}

type AuditWatcher struct {
	id		int
	ctx		context.Context
	eventChannel	chan vfilter.Row
	// Handles logging for each invocation.  The logger itself is
	// threadsafe and we don't need it to be from the same thread as the initial
	// invocation.
	scope		vfilter.Scope
	rules		map[string]*AuditWatcherRule
	auditService	*AuditWatcherService
}

func parseRule(rule string) (*AuditWatcherRule, error) {
	r, err := flags.Parse(rule)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse rule `%s': %v", rule, err)
	}

	wfRule, err := auditrule.Build(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to build rule `%s': %v", rule, err)
	}

	normalizedRule, err := auditrule.ToCommandLine(wfRule, true)
	if err != nil {
		return nil, fmt.Errorf("Failed to normalize rule `%s': %v", rule, err)
	}

	watcherRule := &AuditWatcherRule{
		wfRule:	wfRule,
		rule:	normalizedRule,
	}

	return watcherRule, nil
}

func (self *AuditWatcher) addRules(rules []string) error {
	for _, line := range rules {
		watcherRule, err := parseRule(line)
		if err != nil {
			return err
		}

		_, ok := self.rules[watcherRule.rule]
		if ok {
			return fmt.Errorf("Cannot add duplicate rule `%s' in single query", line)
		}

		self.rules[watcherRule.rule] = watcherRule
		self.scope.Log("audit: added rule `%s' to watcher", watcherRule.rule)
	}

	return nil
}

func (self *AuditWatcher) deleteRules() {
	var logError error = nil

	for name, rule := range self.rules {
		err := self.auditService.deleteRule(rule)
		if err != nil && logError == nil {
			logError = err
		}

		delete(self.rules, name)
	}

	if logError != nil {
		self.scope.Log("audit: Unable to remove all rules during query exit: %v", logError)
	}
}

func (self *AuditWatcher) disconnect() {
	if len(self.rules) > 0 {
		self.deleteRules()
	}
}

type RefcountedAuditWatcherRule struct {
	rule		AuditWatcherRule
	refcount	int
}

type AuditWatcherService struct {
	rulesLock	sync.Mutex
	rules		map[string]*RefcountedAuditWatcherRule
	bannedRules	map[string]*AuditWatcherRule

	watcherLock	sync.RWMutex
	watchers	map[int]*AuditWatcher
	nextWatcherId	int

	listenClient	*libaudit.AuditClient
	commandClient	*libaudit.AuditClient
	reassembler	*libaudit.Reassembler

	wg		sync.WaitGroup
	wgCounter	int64
	ctx		context.Context
	cancel		func()
	logger		*logging.LogContext

	checkerChannel	chan aucoalesce.Event
	startupOnce	sync.Once
	refcount	int64

	epollFd		int
}

// These can probably be removed but they're useful for
// debugging which goroutines are outstanding.  Do not use self.logger
// for printing here as it does its own internal locking so we end up
// serializing when we don't want to.
func (self *AuditWatcherService) wgInc(description string) {
	if debugGoRoutines {
		val := atomic.AddInt64(&self.wgCounter, 1)
		fmt.Printf("audit: wgcounter+: %d [%s]\n", val, description)
	}
	self.wg.Add(1)
}

func (self *AuditWatcherService) wgDec(description string) {
	if debugGoRoutines {
		val := atomic.AddInt64(&self.wgCounter, -1)
		fmt.Printf("audit: wgcounter-: %d [%s]\n", val, description)
	}
	self.wg.Done()
}

// Only allow a reference if the refcount is already elevated
func (self *AuditWatcherService) Get() bool {
	for {
		refcount := atomic.LoadInt64(&self.refcount)

		if refcount == 0 {
			return false
		}

		if atomic.CompareAndSwapInt64(&self.refcount, refcount, refcount + 1) {
			break
		}
	}

	return true
}

func (self *AuditWatcherService) Put() {
	atomic.AddInt64(&self.refcount, -1)

	// If it's the last regular reference, we'll clean up the
	// global reference.
	if atomic.CompareAndSwapInt64(&self.refcount, 1, 0) {
		gService = nil
		self.shutdown()
	}
}

func (self *AuditWatcherService) setupWatcherService() error {
	var err error

	for _, rule := range gBannedRules {
		watcherRule, err := parseRule(rule)
		if err != nil {
			self.logger.Warn("audit: Failed to parse built-in banned rule `%s': %v",
					 rule, err)
			return err
		}

		self.bannedRules[watcherRule.rule] = watcherRule
	}

	self.commandClient, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return err
	}

	status, err := self.commandClient.GetStatus()
	if err != nil {
		self.commandClient.Close()
		return err
	}

	if status.Enabled == 0 {
		self.logger.Info("audit: enabling kernel audit subsystem")
		err = self.commandClient.SetEnabled(true, libaudit.WaitForReply)
		if err != nil {
			self.commandClient.Close()
			return err
		}
	}

	self.listenClient, err = libaudit.NewMulticastAuditClient(nil)
	if err != nil {
		self.commandClient.Close()
		return err
	}

	self.reassembler, err = libaudit.NewReassembler(5, 2*time.Second, self)
	if err != nil {
		self.commandClient.Close()
		self.listenClient.Close()
		return err
	}

	self.ctx, self.cancel = context.WithCancel(context.Background())

	return nil
}

func getAuditWatcherService(config_obj *config_proto.Config) (*AuditWatcherService, error) {

	logger := logging.GetLogger(config_obj, &logging.ClientComponent)

	for {
		svc := gService
		if svc != nil {
			if svc.Get() {
				return svc, nil
			}

			svc.wg.Wait()
		}

		// One at a time, please
		gLock.Lock()

		if gService != nil {
			gLock.Unlock()
			continue
		}

		logger.Info("audit: creating new service instance")

		auditService := &AuditWatcherService{
			rules:		map[string]*RefcountedAuditWatcherRule{},
			bannedRules:	map[string]*AuditWatcherRule{},
			watchers:	map[int]*AuditWatcher{},
			logger:		logger,
			checkerChannel:	make(chan aucoalesce.Event),
			refcount:	1,
		}

		err := auditService.setupWatcherService()
		if err != nil {
			auditService = nil
		} else {
			gService = auditService
		}

		gLock.Unlock()
		return auditService, err
	}
}

func (self *AuditWatcherService) shutdown() {
	// Signal to listener goroutine to exit
	self.cancel()

	self.reassembler.Close()
	self.listenClient.Close()
	self.commandClient.Close()

	self.reassembler = nil
	self.listenClient = nil
	self.commandClient = nil

	// Don't wait here since disconnectWatchers maintains a wg ref.  It'll wait
	// forever.  The listener loop will likely shutdown last and potentially after
	// a new instance of the service is started up but it's fine since nothing is
	// listening to the old one anymore.
	self.logger.Info("audit: Shut down audit service")
}

func (self *AuditWatcherService) acceptEvents() error {

	// We're in non-blocking mode.  Try to get all of the events we can in one go.
	for {
		// We don't have access to the underlying socket to
		// use syscall.Select() to wait for events.  Practically
		// speaking, we'd use a relatively short timeout in Select()
		// to to be able to shut down cleanly.
		rawEvent, err := self.listenClient.Receive(true)
		if err != nil {
			return err
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		line := fmt.Sprintf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
		auditMsg, err := auparse.ParseLogLine(line)
		if err != nil {
			continue
		}
		self.reassembler.PushMessage(auditMsg)
	}
}

func (self *AuditWatcherService) listenerEventLoop() {
	defer self.wgDec("listenerEventLoop")
	defer unix.Close(self.epollFd)
	defer self.logger.Debug("audit: listener event loop exited")

	ready := make([]unix.EpollEvent, 2)
	for {
		count, err := unix.EpollWait(self.epollFd, ready, 5000)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			self.logger.Warn("audit: listenerEventLoop exiting after EpollWait returned %v",
					 err)
			self.cancel()
			return
		}

		if self.ctx.Err() != nil {
			return
		}

		if count > 0 {
			err = self.acceptEvents()

			if err != nil {
				if errors.Is(err, unix.EAGAIN) ||
				   errors.Is(err, unix.EWOULDBLOCK) {
					   continue
				}

				// The socket has been closed.
				if errors.Is(err, unix.EBADF) {
					// There likely won't be any listeners left and the socket
					// was closed in shutdown
					self.notifyWatchers("audit: listener socket closed")
					break
				}
				self.notifyWatchers(fmt.Sprintf("audit: receive failed: %s", err))
				continue
			}

		}
	}
}

func (self *AuditWatcherService) startListener() error {
	fd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	self.epollFd = fd

	fd = self.listenClient.Netlink.GetFD()
	err = unix.EpollCtl(self.epollFd, unix.EPOLL_CTL_ADD, fd,
			    &unix.EpollEvent{Events: unix.POLLIN | unix.POLLHUP,
			    Fd: int32(fd)})
	if err != nil {
		unix.Close(int(self.epollFd))
		return err
	}

	self.wgInc("listenerEventLoop")
	go self.listenerEventLoop()

	return nil
}

func (self *AuditWatcherService) startMaintainer() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	defer self.wgDec("startMaintainer")
	defer self.logger.Debug("audit: reassembler maintainer exited")

	for {
		select {
		case <-self.ctx.Done():
			return

		case <-t.C:
			// Maintain will only return error when closed
			if self.reassembler.Maintain() != nil {
				return
			}
		}
	}
}

func (self *AuditWatcherService) startEventLoops() {
	// Start goroutine to periodically purge timed-out events.
	self.wgInc("startMaintainer")
	go self.startMaintainer()

	self.wgInc("startRulesChecker")
	go self.startRulesChecker(gBatchTimeout)

	err := self.startListener()
	if err != nil {
		self.logger.Warn("Couldn't start listener: %v", err)
		self.cancel()
	}
}

func (self *AuditWatcherService) connectWatcher(ctx context.Context,
						watcher *AuditWatcher) (func(), error) {
	err := self.addRules(&watcher.rules)
	if err != nil {
		return nil, err
	}

	subctx, cancel := context.WithCancel(ctx)

	self.watcherLock.Lock()

	watcher.ctx = subctx
	watcher.id = self.nextWatcherId
	watcher.auditService = self

	self.nextWatcherId += 1
	self.watchers[watcher.id] = watcher

	self.startupOnce.Do(self.startEventLoops)
	self.wgInc("connectWatcher")

	self.watcherLock.Unlock()

	return cancel, nil
}

func (self *AuditWatcherService) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		self.logger.Debug("audit: failed to coalesce message: %v", err)
		return
	}

	// If the configuration has changed, kick off a scan to make sure our rules
	// are still in place
	if event.Category == aucoalesce.EventTypeConfig {
		self.checkerChannel <- *event
	}

	self.distributeEvent(event)
}

func (self *AuditWatcherService) EventsLost(count int) {
	self.notifyWatchers(fmt.Sprintf("Detected the loss of %v sequences.", count))
}

func (self *AuditWatcherService) addRuleToSubsystem(rule *auditrule.WireFormat) error {
	err := self.commandClient.AddRule(*rule)
	if err != nil && !strings.Contains(err.Error(), "rule exists") {
		return err
	}

	return nil
}

func (self *AuditWatcherService) addRule(rule *AuditWatcherRule) error {

	_, ok := self.rules[rule.rule]
	if ok {
		self.rules[rule.rule].refcount += 1
		return nil
	}

	err := self.addRuleToSubsystem(&rule.wfRule)
	if err != nil {
		return err
	}

	self.rules[rule.rule] = &RefcountedAuditWatcherRule{ rule: *rule, refcount: 1 }
	return nil
}

func (self *AuditWatcherService) addRules(rules *map[string]*AuditWatcherRule) error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	for _, rule := range *rules {
		err := self.addRule(rule)
		if err != nil {
			return err
		}
	}

	return nil
}

// Remove a reference to an audit rule.  If it's the last reference, remove it from
// the audit subsystem.
func (self *AuditWatcherService) deleteRule(rule *AuditWatcherRule) error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	_, ok := self.rules[rule.rule]
	if ok {
		self.rules[rule.rule].refcount -= 1
		if self.rules[rule.rule].refcount == 0 {
			delete(self.rules, rule.rule)

			if self.commandClient == nil {
				return fmt.Errorf("audit: ERROR: Race detected between service shutdown and watcher shutdown.  Check locking, even implicit via logging.")
			}

			// If this fails, the rule will be left around
			// There's not a lot we can do about it except perhaps retry later
			// as a TODO
			err := self.commandClient.DeleteRule(rule.wfRule)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (self *AuditWatcherService) disconnectWatcher(watcher *AuditWatcher) {
	watcher.disconnect()

	self.watcherLock.Lock()

	_, ok := self.watchers[watcher.id]
	if ok {
		delete(self.watchers, watcher.id)

		self.watcherLock.Unlock()
		self.wgDec("connectWatcher")
		self.Put()
	} else {
		self.watcherLock.Unlock()
	}
}

func (self *AuditWatcherService) disconnectWatchers(watchers []*AuditWatcher) {
	defer self.wgDec("disconnectWatchers")

	for _, watcher := range watchers {
		self.disconnectWatcher(watcher)
	}
}

func (self *AuditWatcherService) distributeEvent(event *aucoalesce.Event) {
	watchersToDisconnect := []*AuditWatcher{}

	self.watcherLock.RLock()
	for _, watcher := range self.watchers {
		select {
		case <- watcher.ctx.Done():
			watchersToDisconnect = append(watchersToDisconnect, watcher)
		case watcher.eventChannel <- *event:
		}
	}
	self.watcherLock.RUnlock()

	if len(watchersToDisconnect) > 0 {
		self.wgInc("disconnectWatchers")
		go self.disconnectWatchers(watchersToDisconnect)
	}
}

func (self *AuditWatcherService) notifyWatchers(message string) {
	self.watcherLock.RLock()
	defer self.watcherLock.RUnlock()

	for _, watcher := range self.watchers {
		watcher.scope.Log(message)
	}
}

func (self *AuditWatcherService) notifyMissingRule(rule *AuditWatcherRule) {
	self.watcherLock.RLock()
	defer self.watcherLock.RLock()
	count := 0

	for _, watcher := range self.watchers {
		_, ok := watcher.rules[rule.rule]
		if ok {
			watcher.scope.Log("audit: replaced missing rule `%v'", rule.rule)
			count += 1
		}
	}

	if count > 0 {
		self.logger.Info("audit: replaced missing rule `%v'", rule.rule)
	}
}

func (self *AuditWatcherService) checkRules() error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	self.notifyWatchers("audit: detected audit configuration change")
	self.logger.Info("audit: detected audit configuration change")

	missing := 0

	rules, err := self.commandClient.GetRules()
	if err != nil {
		return err
	}

	activeRules := map[string]bool{}

	for _, rule := range rules {
		normalizedRule, err := auditrule.ToCommandLine([]byte(rule), true)
		if err != nil {
			return fmt.Errorf("Failed to normalize rule `%v': %v", rule, err)
		}

		activeRules[normalizedRule] = true
	}

	for text, rule := range self.rules {
		_, ok := activeRules[text]
		if ok {
			continue
		}

		self.notifyMissingRule(&rule.rule)
		err := self.addRuleToSubsystem(&rule.rule.wfRule)
		if err != nil {
			return err
		}
		missing += 1
	}

	if missing > 0 {
		self.logger.Debug("audit: replaced %d missing rules", missing)
	}

	for text, rule := range self.bannedRules {
		_, ok := activeRules[text]
		if !ok {
			continue
		}

		if self.commandClient == nil {
			return fmt.Errorf("audit: ERROR: Race detected between service shutdown and rulesChecker.  Check locking, even implicit via logging.")
		}

		err := self.commandClient.DeleteRule(rule.wfRule)
		if err != nil {
			return err
		}
		self.notifyWatchers(fmt.Sprintf("audit: removed banned rule %v", text))
	}

	return nil
}

// This will allow us to treat a series of rule changes as a single event.  Otherwise, we'll
// end up checking the rules for _every_ event, which is just wasteful.
func (self *AuditWatcherService) startRulesChecker(timeout time.Duration) {
	defer self.wgDec("startRulesChecker")
	defer self.logger.Debug("audit: rules checker exited")

	count := 0

	batchTimeout := time.NewTimer(timeout)
	defer batchTimeout.Stop()

	if !batchTimeout.Stop() {
		<- batchTimeout.C
	}

	for {
		select {
		case <- self.ctx.Done():
			return
		case <- batchTimeout.C:
			err := self.checkRules()
			if err != nil {
				self.logger.Warn("audit: rules check failed %v", err)
			}
			count = 0
		case <- self.checkerChannel:
			batchTimeout.Reset(timeout)
			count += 1
		}
	}
}

type _AuditPluginArgs struct {
	Rules      []string            `vfilter:"optional,field=rules,doc=List of rules"`
}

type AuditPlugin struct{
}

func (self AuditPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "audit",
		Doc:  "Register as an audit daemon in the kernel.",
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

		client_config_obj, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("audit: unable to get config from scope %v", scope)
			return
		}

		config_obj := &config_proto.Config{Client: client_config_obj}

		auditService, err := getAuditWatcherService(config_obj)
		if err != nil {
			scope.Log("audit: Could not get audit watcher service: %v", err)
			return
		}

		watcher := &AuditWatcher{
			scope: scope,
			eventChannel: make(chan vfilter.Row),
			rules: map[string]*AuditWatcherRule{},

		}

		err = watcher.addRules(arg.Rules)
		if err != nil {
			scope.Log("audit: failed to add rules to watcher: %v", err)
			return
		}

		cancel, err := auditService.connectWatcher(ctx, watcher)
		if err != nil {
			scope.Log("audit: failed to connect watcher to audit service: %v", err)
		}

		defer auditService.disconnectWatcher(watcher)
		defer cancel()

		scope.Log("audit: Registered audit watcher")
		defer scope.Log("audit: Unregistered audit watcher")

		for {
			select {
			case <- ctx.Done():
				return
			case event := <- watcher.eventChannel:
				output_chan <- event
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&AuditPlugin{})
}
