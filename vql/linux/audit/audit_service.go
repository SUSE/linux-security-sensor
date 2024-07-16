//go:build linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	auditrule "github.com/elastic/go-libaudit/v2/rule"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/directory"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/vfilter"
)

var (
	mu       sync.Mutex
	gService *auditService

	// Timeout for batching audit configuration events
	gBatchTimeout                 = 1000 * time.Millisecond
	gDebugPrintingEnabled         = false
	gDebugStats                   = false
	gReassemblerMaintainerTimeout = 2 * time.Second
)

var gBannedRules = []string{
	"-d task,never",
}

type AtomicCounter struct {
	value int64
}

func (self *AtomicCounter) Add(val int) int {
	return int(atomic.AddInt64(&self.value, int64(val)))
}

func (self *AtomicCounter) Sub(val int) int {
	return int(atomic.AddInt64(&self.value, -int64(val)))
}

func (self *AtomicCounter) Inc() int {
	return self.Add(1)
}

func (self *AtomicCounter) Dec() int {
	return self.Sub(1)
}

func (self *AtomicCounter) Value() int {
	return int(atomic.LoadInt64(&self.value))
}

func (self *AtomicCounter) String() string {
	return fmt.Sprintf("%v", self.Value())
}

type RefcountedAuditRule struct {
	rule     AuditRule
	refcount int
}

type auditListener interface {
	Open(context.Context) error
	Wait(context.Context) error
	Receive(*auditBuf) error
	Close() error
}

var errRetryNeeded = errors.New("Operation should be retried")

type commandClient interface {
	Open() error
	AddRule(rule []byte) error
	DeleteRule(rule []byte) error
	GetRules() ([][]byte, error)
	GetStatus() (*libaudit.AuditStatus, error)
	SetEnabled(enabled bool, wm libaudit.WaitMode) error
	Close() error
}

type auditService struct {
	config       *config_proto.Config
	serviceWg    sync.WaitGroup
	serviceLock  sync.Mutex
	logger       *logging.LogContext
	listener     auditListener
	nSubscribers int

	rulesLock   sync.Mutex
	rules       map[string]*RefcountedAuditRule
	bannedRules map[string]*AuditRule

	// Once up and running, protected by rulesLock
	commandClient commandClient

	logChannel            chan string
	missingRuleLogChannel chan *AuditRule
	checkerChannel        chan aucoalesce.Event
	running               bool
	shuttingDown          bool
	eventChannel          chan vfilter.Row
	subscribeChannel      chan *subscriber
	unsubscribeChannel    chan *subscriber
	shutdownChan          chan struct{}

	rawBufPool *sync.Pool

	// Used only for stats reporting
	totalMessagesReceivedCounter   AtomicCounter
	totalMessagesDiscardedCounter  AtomicCounter
	totalMessagesDroppedCounter    AtomicCounter
	totalMessagesPostedCounter     AtomicCounter
	totalRowsPostedCounter         AtomicCounter
	totalReceiveLoopCounter        AtomicCounter
	totalOutstandingMessageCounter AtomicCounter
	currentMessagesQueuedCounter   AtomicCounter
}

type auditBuf struct {
	data     []byte
	size     int
	refcount *utils.Refcount
	pool     *sync.Pool
}

func newAuditBuf(bufSize int, pool *sync.Pool) *auditBuf {
	return &auditBuf{
		data:     make([]byte, bufSize),
		refcount: utils.NewRefcount(),
		pool:     pool,
	}
}

func (self *auditBuf) Data() []byte {
	return self.data[:self.size]
}

func (self *auditBuf) Get() {
	self.refcount.Get()
}

func (self *auditBuf) Put() {
	if self.refcount.Put() {
		self.size = 0
		self.refcount.Reset()
		self.pool.Put(self)
	}
}

func newAuditService(config_obj *config_proto.Config, logger *logging.LogContext, listener auditListener, client commandClient) *auditService {
	bufSize := unix.NLMSG_HDRLEN + libaudit.AuditMessageMaxLength
	rawBufPool := &sync.Pool{}

	rawBufPool.New = func() any {
		return newAuditBuf(bufSize, rawBufPool)
	}

	return &auditService{
		config:        config_obj,
		rules:         map[string]*RefcountedAuditRule{},
		bannedRules:   map[string]*AuditRule{},
		rawBufPool:    rawBufPool,
		logger:        logger,
		commandClient: client,
		listener:      listener,
	}
}

func (self *auditService) Debug(format string, v ...interface{}) {
	if gDebugPrintingEnabled {
		self.logger.Debug(format, v...)
	}
}

func (self *auditService) Log(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	self.logger.Info("%s", msg)
	self.logChannel <- msg
}

func (self *auditService) runService() error {
	var err error

	for _, rule := range gBannedRules {
		watcherRule, err := parseRule(rule)
		if err != nil {
			return fmt.Errorf("failed to parse built-in banned rule `%s': %w",
				rule, err)
		}

		self.bannedRules[watcherRule.rule] = watcherRule
	}

	// errgroup doesn't offer a cancel function, so we'll use the hierarchical
	// nature of contexts to get the same result.
	ctx, cancel := context.WithCancel(context.Background())
	grp, grpctx := errgroup.WithContext(ctx)

	err = self.commandClient.Open()
	if err != nil {
		cancel()
		return err
	}

	err = self.listener.Open(grpctx)
	if err != nil {
		cancel()
		self.commandClient.Close()
		return err
	}

	status, err := self.commandClient.GetStatus()
	if err != nil {
		cancel()
		self.commandClient.Close()
		self.listener.Close()
		return err
	}

	if status.Enabled == 0 {
		err = self.commandClient.SetEnabled(true, libaudit.WaitForReply)
		if err != nil {
			cancel()
			self.commandClient.Close()
			self.listener.Close()
			return fmt.Errorf("failed to enable audit subsystem: %w", err)
		}
		self.logger.Info("audit: enabled kernel audit subsystem")
	}

	// Can only fail if self is nil
	reassembler, _ := libaudit.NewReassembler(5, 500*time.Millisecond, self)

	self.logger.Info("audit: starting audit service")
	self.running = true

	options := api.QueueOptions{
		DisableFileBuffering: false,
		FileBufferLeaseSize:  64,
		OwnerName:            "audit-plugin",
	}

	messageQueue, err := directory.NewListenerBytes(self.config, grpctx, options.OwnerName,
							options)
	if err != nil {
		cancel()
		self.commandClient.Close()
		reassembler.Close()
		self.listener.Close()
		self.running = false
		return err
	}

	self.logChannel = make(chan string)
	self.missingRuleLogChannel = make(chan *AuditRule)
	self.checkerChannel = make(chan aucoalesce.Event)
	self.eventChannel = make(chan vfilter.Row)
	self.subscribeChannel = make(chan *subscriber)
	self.unsubscribeChannel = make(chan *subscriber)
	self.shutdownChan = make(chan struct{})

	// For the service
	self.serviceWg.Add(1)

	// For goroutines that exit when channels are closed
	chanWg := sync.WaitGroup{}

	// exits when the log channel is closed
	chanWg.Add(1)
	go func() {
		self.subscriberDistributionLoop()
		close(self.subscribeChannel)
		close(self.unsubscribeChannel)
		chanWg.Done()
	}()

	// exits when the checker channel is closed
	chanWg.Add(1)
	go func() {
		self.startRulesChecker()
		close(self.missingRuleLogChannel)
		chanWg.Done()
	}()

	// For goroutines that exit when the listener has exited
	listenerWg := sync.WaitGroup{}

	// exits when messageQueue is closed
	listenerWg.Add(1)
	go func() {
		self.eventProcessingLoop(messageQueue, reassembler)
		listenerWg.Done()
	}()

	// exits when context is canceled or reassembler is closed
	listenerWg.Add(1)
	grp.Go(func() error {
		self.startMaintainer(grpctx, reassembler)
		listenerWg.Done()
		return nil
	})

	if gDebugStats {
		// exits when context is canceled
		grp.Go(func() error {
			self.reportStats(grpctx)
			return nil
		})
	}

	// exits on error or context cancelation
	grp.Go(func() error {
		// We close the message queue once we flush the events
		err := self.listenerEventLoop(grpctx, messageQueue)
		messageQueue.Close()
		return err
	})

	// Wait until we cancel the context or something hits an error
	go func() {
		self.Debug("audit: shutdown watcher starting")
		defer self.Debug("audit: shutdown watcher exited")

		select {
		case <-grpctx.Done():
			// Shutdown due to error, don't allow new subscribers
			// when the distribution loop exits, it will evict
			// remaining subscribers
			self.serviceLock.Lock()
			self.initiateShutdown()
			self.serviceLock.Unlock()
		case <-self.shutdownChan:
			// Normal shutdown due to zero subscribers
		}

		self.Debug("audit: shutting down")

		// Cancel the top-level context
		cancel()

		// Wait for the listener to exit
		err := grp.Wait()
		if !errors.Is(err, context.Canceled) {
			// This should be rare, a netlink recvfrom() failure
			self.Log("audit: shutting down due to error ; err=%s", err)
		}

		// No new messages will be generated, wait for the event processing loop
		// and reassembler to exit
		listenerWg.Wait()

		// Closing will clean up any remaining incomplete messages
		reassembler.Close()
		close(self.eventChannel)

		// Reassembler is flushed so there won't be any more reconfiguration
		// messages.  We can shut down the rules checker.
		close(self.checkerChannel)

		// Close our sockets
		self.commandClient.Close()
		self.listener.Close()

		// Everything else is shut down so there won't be any more log messages
		// exit the distribution goroutine
		close(self.logChannel)

		// Wait for logger and rules checker to shut down
		chanWg.Wait()

		self.finalizeShutdown()
	}()

	return nil
}

func (self *auditService) finalizeShutdown() {
	self.bannedRules = map[string]*AuditRule{}
	self.rules = map[string]*RefcountedAuditRule{}

	self.logger.Info("audit: Shut down audit service")

	self.serviceLock.Lock()
	self.running = false
	self.shuttingDown = false
	self.serviceLock.Unlock()
	self.serviceWg.Done()
}

func (self *auditService) acceptEvents(ctx context.Context,
				       messageQueue *directory.ListenerBytes) error {
	receivedCount := 0
	discardedCount := 0
	queuedCount := 0

	// We're in non-blocking mode.  Try to get all of the events we can in one go.
	var err error
	for {
		err = ctx.Err()
		if err != nil {
			break
		}

		buf := self.rawBufPool.Get().(*auditBuf)
		msgType, err := self.receiveMessageBuf(buf)
		if err != nil {
			buf.Put()
			// Increased socket receive buffer
			if errors.Is(err, errRetryNeeded) {
				continue
			}

			if errors.Is(err, syscall.EAGAIN) {
				break
			}
			// recvfrom() failure
			return err
		}

		receivedCount += 1

		// Messages from 1300-2999 are valid audit messages.
		if msgType < auparse.AUDIT_USER_AUTH || msgType > auparse.AUDIT_LAST_USER_MSG2 {
			buf.Put()
			discardedCount += 1
			continue
		}

		// Send will take its own reference if needed
		messageQueue.Send(buf)
		buf.Put()
		queuedCount += 1
	}

	self.currentMessagesQueuedCounter.Add(queuedCount)
	self.totalMessagesReceivedCounter.Add(receivedCount)
	self.totalMessagesDiscardedCounter.Add(discardedCount)

	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		err = nil
	}

	return err
}

func (self *auditService) processOneMessage(reassembler *libaudit.Reassembler, buf []byte) error {
	if len(buf) < unix.NLMSG_HDRLEN {
		return syscall.EINVAL
	}
	header := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	msgType := auparse.AuditMessageType(header.Type)
	data := buf[unix.NLMSG_HDRLEN:]

	msgBuf := &auparse.AuditMessage{}
	err := msgBuf.Parse(msgType, string(data))
	if err != nil {
		return err
	}

	reassembler.PushMessage(msgBuf)

	// These record types aren't included in the complete callback
	// but they still need to be pushed
	if msgBuf.RecordType == auparse.AUDIT_EOE {
		return nil
	}
	self.totalOutstandingMessageCounter.Inc()
	return nil
}

func (self *auditService) addSubscriberRules(subscriber *subscriber) error {
	added := []*AuditRule{}

	for _, rule := range subscriber.rules {
		err := self.addRule(rule)
		if err != nil {
			// This will at minimum roll back the refcounts
			for _, addedRule := range added {
				self.deleteRule(addedRule)
			}
			return err
		}
		added = append(added, rule)
	}

	return nil
}

func (self *auditService) removeSubscriberRules(subscriber *subscriber) error {
	for _, rule := range subscriber.rules {
		err := self.deleteRule(rule)
		if err != nil {
			msg := fmt.Sprintf("audit: failed to remove rule `%s' during unsubscribe: %s", rule.rule, err)
			subscriber.logChannel <- msg
			continue
		}
	}

	return nil
}

// exits when the listener message queue is closed
func (self *auditService) eventProcessingLoop(messageQueue *directory.ListenerBytes,
					      reassembler *libaudit.Reassembler) {
	self.Debug("audit: eventProcessingLoop started")
	defer self.Debug("audit: eventProcessingLoop exited")

	for {
		select {
		// We wait on the messageQueue to close instead of the
		// context to be done.  The context is shared with the
		// listener event loop and we want to ensure the listener
		// has flushed its messages.
		case buf, ok := <-messageQueue.Output():
			if !ok {
				return
			}
			err := self.processOneMessage(reassembler, buf.Data())
			if err != nil {
				self.logger.Info("failed to parse message: %v", err)
			}
			buf.Put()
			self.currentMessagesQueuedCounter.Dec()
		}
	}
}

// exits when a channel is closed
func (self *auditService) subscriberDistributionLoop() {
	self.Debug("audit: subscriber distribution loop started")
	defer self.Debug("audit: subscriber distribution loop exited")

	subscribers := []*subscriber{}
	defer func() {
		self.evictSubscribers(subscribers)
	}()
	for {
		select {
		case msg, ok := <-self.logChannel:
			if !ok {
				return
			}

			for _, subscriber := range subscribers {
				subscriber.logChannel <- msg
			}
			self.logger.Info(msg)
		case rule, ok := <-self.missingRuleLogChannel:
			if !ok {
				return
			}
			var msg string
			for _, subscriber := range subscribers {
				_, ok := subscriber.rules[rule.rule]
				if !ok {
					continue
				}
				if msg == "" {
					msg = fmt.Sprintf("audit: replaced missing rule `%v'", rule.rule)
				}
				subscriber.logChannel <- msg
			}

		case event, ok := <-self.eventChannel:
			if !ok {
				return
			}
			for _, subscriber := range subscribers {
				subscriber.eventChannel <- event
			}
		case subscriber, _ := <-self.subscribeChannel:
			subscribers = append(subscribers, subscriber)
			self.Debug("audit: adding subscriber, total now %v", len(subscribers))
			subscriber.wait.Done()
		case subscriber, _ := <-self.unsubscribeChannel:
			for i, sub := range subscribers {
				if sub != subscriber {
					continue
				}

				newlen := len(subscribers) - 1
				subscribers[i] = subscribers[newlen]
				subscribers = subscribers[:newlen]
				break
			}

			self.Debug("audit: removing subscriber, total now %v", len(subscribers))

			subscriber.wait.Done()
		}
	}
}

func (self *auditService) evictSubscribers(subscribers []*subscriber) {
	// Evict remaining subscribers if we shut down due to error
	if len(subscribers) > 0 {
		self.logger.Info("audit: Evicting remaining %d subscribers", len(subscribers))
		for _, subscriber := range subscribers {
			self.unsubscribe(subscriber)
		}
	}
}

func (self *auditService) listenerEventLoop(ctx context.Context,
					    messageQueue *directory.ListenerBytes) error {
	self.Debug("audit: listener event loop started")
	defer self.Debug("audit: listener event loop exited")

	for {
		err := self.listener.Wait(ctx)
		if err != nil {
			return err
		}

		self.totalReceiveLoopCounter.Inc()
		err = self.acceptEvents(ctx, messageQueue)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}

			self.Log("audit: acceptEvents %v", err)
			return err
		}
	}
}

func (self *auditService) reportStats(ctx context.Context) {
	lastReceived := 0
	lastDiscarded := 0
	lastDropped := 0
	lastQueued := 0
	lastPosted := 0
	lastMessagesPosted := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		received := self.totalMessagesReceivedCounter.Value()
		discarded := self.totalMessagesDiscardedCounter.Value()
		dropped := self.totalMessagesDroppedCounter.Value()
		posted := self.totalRowsPostedCounter.Value()
		messagesPosted := self.totalMessagesPostedCounter.Value()
		queued := self.currentMessagesQueuedCounter.Value()
		loops := self.totalReceiveLoopCounter.Value()
		outstandingMsgs := self.totalOutstandingMessageCounter.Value()
		if loops == 0 {
			loops = 1
		}

		self.logger.Debug("audit: ******************************** Received %d messages (%d rows) from kernel (diff %d (%d rows)) (averaging %d messages per loop over %d loops)",
			received, received/6, received-lastReceived,
			(received-lastReceived)/6, received/loops, loops)
		self.logger.Debug("audit: ******************************** Discarded %d messages from kernel (diff %d)",
			discarded, discarded-lastDiscarded)

		self.logger.Debug("audit: ******************************** %d messages dropped (diff %d)",
			dropped, dropped-lastDropped)
		self.logger.Debug("audit: ******************************** %d messages posted (diff %d) (delta %v)",
			messagesPosted, messagesPosted-lastMessagesPosted,
			received-dropped-messagesPosted-queued-discarded)
		self.logger.Debug("audit: ******************************** %d rows posted (diff %d)",
			posted, posted-lastPosted)

		self.logger.Debug("audit: ******************************** %d messages still queued (%d rows) (diff %d (%d rows))",
			queued, queued/6, queued-lastQueued, (queued-lastQueued)/6)

		self.logger.Debug("audit: ******************************** current message count: %d",
			outstandingMsgs)

		lastReceived = received
		lastDiscarded = discarded
		lastDropped = dropped
		lastPosted = posted
		lastQueued = queued
		lastMessagesPosted = messagesPosted
	}
}

// exits when the reassembler is closed or the context is canceled.
func (self *auditService) startMaintainer(ctx context.Context, reassembler *libaudit.Reassembler) {
	self.Debug("audit: reassembler maintainer started")
	defer self.Debug("audit: reassembler maintainer exited")

	for {
		select {
		case <-ctx.Done():
			return

		case <-time.After(gReassemblerMaintainerTimeout):
			// Maintain will only return error when closed
			if reassembler.Maintain() != nil {
				return
			}
		}
	}
}

// This executes as a synchronous callback via Reassembler.PushMessage
func (self *auditService) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)

	self.totalOutstandingMessageCounter.Sub(len(msgs))

	if err != nil {
		self.logger.Info("audit: failed to coalesce message: %v", err)
		return
	}

	// If the configuration has changed, kick off a scan to make sure our rules
	// are still in place
	if event.Category == aucoalesce.EventTypeConfig {
		self.checkerChannel <- *event
	}

	self.eventChannel <- *event
	self.totalRowsPostedCounter.Inc()
}

func (self *auditService) EventsLost(count int) {
	if count > 0x80000000 {
		count = 0x100000000 - count
	}
	self.Log("audit: Detected the loss of %v sequences.", count)
	self.totalMessagesDroppedCounter.Add(count)
}

func (self *auditService) addRuleToSubsystem(rule *auditrule.WireFormat) error {
	err := self.commandClient.AddRule(*rule)
	if err != nil && !strings.Contains(err.Error(), "rule exists") {
		return err
	}

	return nil
}

func (self *auditService) addRule(rule *AuditRule) error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	_, ok := self.rules[rule.rule]
	if ok {
		self.rules[rule.rule].refcount += 1
		return nil
	}

	err := self.addRuleToSubsystem(&rule.wfRule)
	if err != nil {
		return err
	}

	self.rules[rule.rule] = &RefcountedAuditRule{rule: *rule, refcount: 1}
	return nil
}

// Remove a reference to an audit rule.  If it's the last reference, remove it from
// the audit subsystem.
func (self *auditService) deleteRule(rule *AuditRule) error {
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

func (self *auditService) checkRules() error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

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

		self.missingRuleLogChannel <- &rule.rule

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
		self.Log("audit: removed banned rule %v", text)
	}

	return nil
}

// This will allow us to treat a series of rule changes as a single event.  Otherwise, we'll
// end up checking the rules for _every_ event, which is just wasteful.
// Exits when checkerChannel is closed since it consumes events from ReassemblyComplete
func (self *auditService) startRulesChecker() {
	self.Debug("audit: rules checker started")
	defer self.Debug("audit: rules checker exited")

	for {
		select {
		case <-time.After(gBatchTimeout):
			err := self.checkRules()
			if err != nil {
				self.logger.Warn("audit: rules check failed %v", err)
			}
		case _, ok := <-self.checkerChannel: // Wait for config change event
			if !ok {
				return
			}
		}
	}
}

func (self *auditService) receiveMessageBuf(buf *auditBuf) (msgType auparse.AuditMessageType, err error) {
	if len(buf.data) < unix.NLMSG_HDRLEN {
		err = syscall.EINVAL
		return
	}

	err = self.listener.Receive(buf)
	if err != nil {
		return
	}

	header := *(*unix.NlMsghdr)(unsafe.Pointer(&buf.data[0]))
	msgType = auparse.AuditMessageType(header.Type)
	return
}

func (self *auditService) unsubscribe(subscriber *subscriber) {
	// Not an error; Shutdown and caller-initiated unsubscribe can happen
	// concurrently.  Both will take the subscriberLock.
	if subscriber.subscribed {
		_ = self.removeSubscriberRules(subscriber)
		subscriber.disconnect()
	}
}

// It's possible for another subscriber to attempt to start the
// service and then fail, which will shut it down again.
// Expects that the caller holds serviceLock
func (self *auditService) waitForShutdown() {
	for {
		if !self.shuttingDown {
			return
		}

		// Wait for previous instance to shut down
		self.serviceLock.Unlock()
		self.serviceWg.Wait()
		self.serviceLock.Lock()
	}
}

// Expects that the caller holds serviceLock
func (self *auditService) initiateShutdown() {
	if !self.shuttingDown {
		self.shuttingDown = true
		self.nSubscribers = 0
		close(self.shutdownChan)
	}
}

func (self *auditService) Subscribe(rules []string) (AuditEventSubscriber, error) {
	subscriber := newSubscriber()

	err := subscriber.addRules(rules)
	if err != nil {
		return nil, err
	}

	self.serviceLock.Lock()
	self.waitForShutdown()

	// Service was started by another caller
	if self.nSubscribers == 0 {
		err = self.runService()
		if err != nil {
			self.serviceLock.Unlock()
			return nil, err
		}
	}

	err = subscriber.connect()
	if err != nil {
		if self.nSubscribers == 0 {
			self.initiateShutdown()
		}
		self.serviceLock.Unlock()
		return nil, err
	}

	err = self.addSubscriberRules(subscriber)
	if err != nil {
		if self.nSubscribers == 0 {
			self.initiateShutdown()
		}
		self.serviceLock.Unlock()
		return nil, err
	}

	self.nSubscribers += 1
	self.serviceLock.Unlock()

	subscriber.wait.Add(1)
	self.subscribeChannel <- subscriber
	subscriber.wait.Wait()

	return subscriber, nil
}

func (self *auditService) Unsubscribe(auditSubscriber AuditEventSubscriber) {
	subscriber := auditSubscriber.(*subscriber)
	if !subscriber.isSubscribed() {
		return
	}

	// Continue to drain events/messages until we're disconnected
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case _, ok := <-subscriber.logChannel:
				if !ok {
					return
				}
			case _, ok := <-subscriber.eventChannel:
				if !ok {
					return
				}
			}
		}
	}()

	subscriber.wait.Add(1)
	self.unsubscribeChannel <- subscriber
	subscriber.wait.Wait()

	self.unsubscribe(subscriber)
	wg.Wait()

	// Last subscriber - shut it down
	self.serviceLock.Lock()
	self.nSubscribers -= 1
	if self.nSubscribers == 0 {
		self.initiateShutdown()
	}
	self.serviceLock.Unlock()
}

type AuditEventSubscriber interface {
	Events() chan vfilter.Row
	LogEvents() chan string
}

type AuditService interface {
	Subscribe(rules []string) (AuditEventSubscriber, error)
	Unsubscribe(AuditEventSubscriber)
}

func GetAuditService(config_obj *config_proto.Config) (AuditService, error) {
	logger := logging.GetLogger(config_obj, &logging.ClientComponent)
	mu.Lock()
	defer mu.Unlock()

	if gService == nil {
		client := NewCommandClient()
		listener := NewAuditListener()
		gService = newAuditService(config_obj, logger, listener, client)
	}

	return AuditService(gService), nil
}
