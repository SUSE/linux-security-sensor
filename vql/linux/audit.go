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
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Velocidex/ordereddict"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	auditrule "github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/scryner/lfreequeue"
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
	gDebugPrintingEnabled = false
	gMinimumSocketBufSize = 512 * 1024
	gMaxMessageQueueDepth = int64(2500)
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
	pendingDisconnect	bool
	disconnecting	int64
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
	// Disconnects can be initiated by distributeEvent and by channel shutdown.
	// We only want to do this once.
	if atomic.CompareAndSwapInt64(&self.disconnecting, 0, 1) {
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
	// Once up and running, protected by rulesLock
	commandClient	*libaudit.AuditClient
	reassembler	*libaudit.Reassembler

	wg		sync.WaitGroup
	serviceWg	sync.WaitGroup
	wgCounter	int64
	ctx		context.Context
	cancel		func()
	logger		*logging.LogContext

	checkerChannel	chan aucoalesce.Event
	startupOnce	sync.Once
	refcount	int64

	epollFd		int
	listenSocketBufSize int

	eventQueue	*lfreequeue.Queue
	queueFlushTimer	*time.Timer
	queueFlushMutex	sync.Mutex
	bufPool		sync.Pool

	// Used only for stats reporting
	totalMessagesReceivedCounter	int64
	totalMessagesDiscardedCounter	int64
	totalMessagesDroppedCounter	int64
	totalMessagesPostedCounter	int64
	totalRowsPostedCounter		int64
	totalReceiveLoopCounter		int64
	totalOutstandingBufferCounter	int64
	currentMessagesQueuedCounter	int64
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

func (self *AuditWatcherService) Debug(format string, v ...interface{}) {
	if gDebugPrintingEnabled {
		self.logger.Debug(format, v...)
	}
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
		// Doesn't need wgInc - it is owned by serviceWg
		go self.shutdown()
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

	fd := self.listenClient.Netlink.GetFD()

	self.listenSocketBufSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		self.logger.Warn("audit: could not get socket receive buffer size: %v", err)
		return err
	}

	if self.listenSocketBufSize < gMinimumSocketBufSize {
		err = self.resetListenSocketBufSize(gMinimumSocketBufSize)
		if err != nil {
			self.commandClient.Close()
			self.listenClient.Close()
			return err
		}
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

func (self *AuditWatcherService) resetListenSocketBufSize(bufSize int) error {
	var err error

	fd := self.listenClient.Netlink.GetFD()

	if bufSize == 0 {
		bufSize = self.listenSocketBufSize
		if bufSize == 0 {
			bufSize, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
			if err != nil {
				self.logger.Warn("audit: could not get socket receive buffer size: %v", err)
				return err
			}
		}

		bufSize *= 4
	}

	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bufSize)
	if err != nil {
		self.logger.Warn("audit: could not set socket receive buffer size: %v", err)
		return err
	}

	self.listenSocketBufSize = bufSize

	self.logger.Info("audit: receive buffer size set to %d bytes", bufSize)

	return nil
}

func newStoppedTimer() *time.Timer {
	timer := time.NewTimer(0)
	<- timer.C

	return timer
}

func getAuditWatcherService(config_obj *config_proto.Config) (*AuditWatcherService, error) {

	logger := logging.GetLogger(config_obj, &logging.ClientComponent)

	for {
		svc := gService
		if svc != nil {
			if svc.Get() {
				return svc, nil
			}

			svc.serviceWg.Wait()
		}

		// One at a time, please
		gLock.Lock()

		if gService != nil {
			gLock.Unlock()
			continue
		}

		logger.Info("audit: creating new service instance")

		bufSize := unix.NLMSG_HDRLEN + libaudit.AuditMessageMaxLength
		pool := sync.Pool {
			New: func() interface{} {
				return &AuditMessageBuf{ Data: make([]byte, bufSize) }
			},
		}

		auditService := &AuditWatcherService{
			rules:		map[string]*RefcountedAuditWatcherRule{},
			bannedRules:	map[string]*AuditWatcherRule{},
			watchers:	map[int]*AuditWatcher{},
			logger:		logger,
			checkerChannel:	make(chan aucoalesce.Event),
			refcount:	1,
			eventQueue:	lfreequeue.NewQueue(),
			bufPool:	pool,
		}

		auditService.queueFlushTimer = newStoppedTimer()

		err := auditService.setupWatcherService()
		if err != nil {
			auditService = nil
		} else {
			auditService.serviceWg.Add(1)
			gService = auditService
		}

		gLock.Unlock()
		return auditService, err
	}
}

func (self *AuditWatcherService) shutdown() {
	// Signal to listener goroutine to exit
	self.cancel()

	self.wg.Wait()

	self.reassembler.Close()
	self.listenClient.Close()
	self.commandClient.Close()

	self.reassembler = nil
	self.listenClient = nil
	self.commandClient = nil

	self.logger.Info("audit: Shut down audit service")
	self.serviceWg.Done()
}

type AuditMessageBuf struct {
	AuditMessage	auparse.AuditMessage
	Message		libaudit.RawAuditMessage
	Data		[]byte
}

func (self *AuditWatcherService) acceptEvents() error {
	defer atomic.AddInt64(&self.totalReceiveLoopCounter, 1)

	var receivedCount int64 = 0
	var discardedCount int64 = 0
	var queuedCount int64 = 0

	defer self.queueFlushTimer.Reset(500 * time.Millisecond)

	queueDepth := atomic.LoadInt64(&self.currentMessagesQueuedCounter)

	// We're in non-blocking mode.  Try to get all of the events we can in one go.
	for {
		recvBuf := self.bufPool.Get().(*AuditMessageBuf)
		err := self.ReceiveMessageBuf(recvBuf)
		if err != nil {
			self.bufPool.Put(recvBuf)
			atomic.AddInt64(&self.currentMessagesQueuedCounter, queuedCount)
			atomic.AddInt64(&self.totalMessagesReceivedCounter, receivedCount)
			atomic.AddInt64(&self.totalMessagesDiscardedCounter, discardedCount)
			atomic.AddInt64(&self.totalOutstandingBufferCounter, receivedCount)
			return err
		}

		receivedCount += 1

		rawEvent := recvBuf.Message

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			self.bufPool.Put(recvBuf)
			discardedCount += 1
			continue
		}

		if queueDepth + queuedCount >= gMaxMessageQueueDepth {
			atomic.AddInt64(&self.currentMessagesQueuedCounter, queuedCount)
			queuedCount = 0
			self.flushEventQueue()
			queueDepth = atomic.LoadInt64(&self.currentMessagesQueuedCounter)
		}

		self.eventQueue.Enqueue(recvBuf)
		queuedCount += 1

		if (queuedCount % 500) == 0 {
			self.queueFlushTimer.Reset(500 * time.Millisecond)
		}
	}
}

func (self *AuditWatcherService) flushEventQueue() {
	self.queueFlushMutex.Lock()
	defer self.queueFlushMutex.Unlock()
	events := atomic.LoadInt64(&self.currentMessagesQueuedCounter)
	if events == 0 {
		return
	}
	self.Debug("draining %v events from queue", events)
	then := time.Now()

	count := int64(0)

	for count < events {
		item, _ := self.eventQueue.Dequeue()
		if item == nil {
			break
		}

		count += 1

		recvBuf := item.(*AuditMessageBuf)

		err := auparse.ParseBytes(recvBuf.Message.Type, recvBuf.Message.Data,
					  &recvBuf.AuditMessage)
		if err != nil {
			self.Debug("Failed to parse message: %v", err)
			atomic.AddInt64(&self.totalOutstandingBufferCounter, -1)
			self.bufPool.Put(recvBuf)
			continue
		}

		// Allows the ReassemblyComplete callback to free the buffer
		recvBuf.AuditMessage.Owner = recvBuf

		self.reassembler.PushMessage(&recvBuf.AuditMessage)
		atomic.AddInt64(&self.totalMessagesPostedCounter, 1)

		// These record types aren't included in the complete callback
		// but they still need to be pushed
		if recvBuf.AuditMessage.RecordType == auparse.AUDIT_EOE {
			atomic.AddInt64(&self.totalOutstandingBufferCounter, -1)
			self.bufPool.Put(recvBuf)
		}
	}

	atomic.AddInt64(&self.currentMessagesQueuedCounter, -count)
	elapsed := time.Now().Sub(then)
	self.Debug("drained %v events from queue in %v", count, elapsed)
}

// Ensure that no events sit in the queue for more than 500ms
func (self *AuditWatcherService) startEventQueueMaintainer() {
	defer self.wgDec("startEventQueueMaintainer")

	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.queueFlushTimer.C:
			self.Debug("Timer fired")
			self.flushEventQueue()
		}
	}
}

func (self *AuditWatcherService) listenerEventLoop() {
	defer self.wgDec("listenerEventLoop")
	defer unix.Close(self.epollFd)
	defer self.Debug("audit: listener event loop exited")

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

		if count == 0 {
			continue
		}

		err = self.acceptEvents()
		if err != nil {
			if errors.Is(err, unix.EAGAIN) ||
			   errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}

			if errors.Is(err, unix.ENOBUFS) {
				err = self.resetListenSocketBufSize(0)
				if err != nil {
					msg := fmt.Sprintf("audit: failed to increase listener socket buffer size: %v.  Events may be lost.", err)
					self.notifyWatchers(msg)
				}
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

func (self *AuditWatcherService) reportStats() {
	self.wgDec("reportStats")
	timeout := time.NewTicker(5 * time.Second)
	defer timeout.Stop()

	lastReceived := int64(0)
	lastDiscarded := int64(0)
	lastDropped := int64(0)
	lastQueued := int64(0)
	lastPosted := int64(0)
	lastMessagesPosted := int64(0)

	for {
		select {
		case <-self.ctx.Done():
			return
		case <- timeout.C:
			break
		}

		received := atomic.LoadInt64(&self.totalMessagesReceivedCounter)
		discarded := atomic.LoadInt64(&self.totalMessagesDiscardedCounter)
		dropped := atomic.LoadInt64(&self.totalMessagesDroppedCounter)
		posted := atomic.LoadInt64(&self.totalRowsPostedCounter)
		messagesPosted := atomic.LoadInt64(&self.totalMessagesPostedCounter)
		queued := atomic.LoadInt64(&self.currentMessagesQueuedCounter)
		loops := atomic.LoadInt64(&self.totalReceiveLoopCounter)
		if loops == 0 {
			loops = 1
		}

		self.logger.Debug("audit: ******************************** Received %d messages (%d rows) from kernel (diff %d (%d rows)) (averaging %d messages per loop over %d loops)",
		                  received, received / 6, received - lastReceived,
		                  (received - lastReceived) / 6, received / loops, loops)
		self.logger.Debug("audit: ******************************** Discarded %d messages from kernel (diff %d)",
				  discarded, discarded - lastDiscarded)

		self.logger.Debug("audit: ******************************** %d messages dropped (diff %d)",
		                  dropped, dropped - lastDropped)
		self.logger.Debug("audit: ******************************** %d messages posted (diff %d) (delta %v)",
		                  messagesPosted, messagesPosted - lastMessagesPosted,
				  received - dropped - messagesPosted - queued - discarded)
		self.logger.Debug("audit: ******************************** %d rows posted (diff %d)",
		                  posted, posted - lastPosted)

		self.logger.Debug("audit: ******************************** %d messages still queued (%d rows) (diff %d (%d rows))",
		                  queued, queued/6, queued - lastQueued, (queued - lastQueued) / 6)

		self.logger.Debug("audit: ******************************** current buf size: %d",
				  self.listenSocketBufSize)
		self.logger.Debug("audit: ******************************** current buffer count: %d",
				  self.totalOutstandingBufferCounter)

		lastReceived = received
		lastDiscarded = discarded
		lastDropped = dropped
		lastPosted = posted
		lastQueued = queued
		lastMessagesPosted = messagesPosted
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

	if gDebugPrintingEnabled {
		self.wgInc("reportStats()")
		go self.reportStats()
	}

	return nil
}

func (self *AuditWatcherService) startMaintainer() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	defer self.wgDec("startMaintainer")
	defer self.Debug("audit: reassembler maintainer exited")

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

	self.wgInc("startEventQueueMaintainer")
	go self.startEventQueueMaintainer()

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
		self.logger.Info("audit: failed to coalesce message: %v", err)
		return
	}

	// Free the buffer for reuse
	for _, msg := range msgs {
		self.bufPool.Put(msg.Owner)
	}
	atomic.AddInt64(&self.totalOutstandingBufferCounter, -int64(len(msgs)))

	// If the configuration has changed, kick off a scan to make sure our rules
	// are still in place
	if event.Category == aucoalesce.EventTypeConfig {
		self.checkerChannel <- *event
	}

	self.distributeEvent(event)
}

func (self *AuditWatcherService) EventsLost(count int) {
	self.notifyWatchers(fmt.Sprintf("Detected the loss of %v sequences.", count))
	atomic.AddInt64(&self.totalMessagesDroppedCounter, int64(count))
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

	atomic.AddInt64(&self.totalRowsPostedCounter, 1)

	self.watcherLock.RLock()
	for _, watcher := range self.watchers {
		select {
		case <- watcher.ctx.Done():
			if !watcher.pendingDisconnect {
				watchersToDisconnect = append(watchersToDisconnect, watcher)
				watcher.pendingDisconnect = true
			}
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
		self.Debug("audit: replaced %d missing rules", missing)
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
	defer self.Debug("audit: rules checker exited")

	count := 0

	batchTimeout := newStoppedTimer()

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

func (self *AuditWatcherService) ReceiveMessageBuf(msgBuf *AuditMessageBuf) error {
	if len(msgBuf.Data) < unix.NLMSG_HDRLEN {
		return unix.EINVAL
	}

	flags := unix.MSG_DONTWAIT

	fd := self.listenClient.Netlink.GetFD()

	// XXX (akroh): A possible enhancement is to use the MSG_PEEK flag to
	// check the message size and increase the buffer size to handle it all.
	nr, from, err := unix.Recvfrom(fd, msgBuf.Data, flags)
	if err != nil {
		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return err
	}
	if nr < unix.NLMSG_HDRLEN {
		return fmt.Errorf("not enough bytes (%v) received to form a netlink header", nr)
	}
	fromNetlink, ok := from.(*unix.SockaddrNetlink)
	if !ok || fromNetlink.Pid != 0 {
		// Spoofed packet received on audit netlink socket.
		return errors.New("message received was not from the kernel")
	}

	buf := msgBuf.Data[:nr]

	header := *(*unix.NlMsghdr)(unsafe.Pointer(&msgBuf.Data[0]))
	msgBuf.Message.Type   = auparse.AuditMessageType(header.Type)
	msgBuf.Message.Data   = buf[unix.NLMSG_HDRLEN:]

	return nil
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

		_, err = auditService.connectWatcher(ctx, watcher)
		if err != nil {
			scope.Log("audit: failed to connect watcher to audit service: %v", err)
		}

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
