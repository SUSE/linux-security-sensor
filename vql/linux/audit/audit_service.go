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

type commandClient interface {
	AddRule(rule []byte) error
	DeleteRule(rule []byte) error
	GetRules() ([][]byte, error)
	GetStatus() (*libaudit.AuditStatus, error)
	SetEnabled(enabled bool, wm libaudit.WaitMode) error
	Close() error
}

type auditService struct {
	config      *config_proto.Config
	serviceWg   sync.WaitGroup
	serviceLock sync.Mutex
	logger      *logging.LogContext

	rulesLock   sync.Mutex
	rules       map[string]*RefcountedAuditRule
	bannedRules map[string]*AuditRule

	// Once up and running, protected by rulesLock
	commandClient commandClient
	reassembler   *libaudit.Reassembler
	listener auditListener

	logChannel     chan string
	checkerChannel chan aucoalesce.Event
	running        bool
	shuttingDown   bool
	cancelService  func()

	messageQueue *directory.ListenerBytes

	rawBufPool sync.Pool

	subscriberLock sync.RWMutex
	subscribers    []*subscriber

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
	data []byte
	size int
	refcount utils.Refcount
	pool *sync.Pool
}

func newAuditBuf(bufSize int, pool *sync.Pool) *auditBuf {
	return &auditBuf{
		data: make([]byte, bufSize, bufSize),
		refcount: utils.NewRefcount(),
		pool: pool,
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
		self.pool.Put(self)
	}
}

type auditBufs struct {
	pool *sync.Pool
}

func newAuditService(config_obj *config_proto.Config, logger *logging.LogContext, listener auditListener, client commandClient) *auditService {
	bufSize := unix.NLMSG_HDRLEN + libaudit.AuditMessageMaxLength
	rawBufPool := sync.Pool{}

	rawBufPool.New = func() any {
		return newAuditBuf(bufSize, &rawBufPool)
	}

	return &auditService{
		config:      config_obj,
		rules:       map[string]*RefcountedAuditRule{},
		bannedRules: map[string]*AuditRule{},
		rawBufPool:  rawBufPool,
		subscribers: []*subscriber{},
		logger:      logger,
		commandClient: client,
		listener:    listener,
	}
}

func (self *auditService) Debug(format string, v ...interface{}) {
	if gDebugPrintingEnabled {
		self.logger.Debug(format, v...)
	}
}

func (self *auditService) runService() error {
	var err error

	defer self.serviceLock.Unlock()
	self.serviceLock.Lock()

	// It's possible for another subscriber to attempt to start the
	// service and then fail, which will shut it down again.  We only
	// exit the loop in a known state: service is running or we need to
	// start it.
	for {
		if self.running {
			if !self.shuttingDown {
				return nil
			}

			// Wait for previous instance to shut down
			self.serviceLock.Unlock()
			self.serviceWg.Wait()
			self.serviceLock.Lock()
			continue
		}
		// Start the service
		break
	}

	self.logChannel = make(chan string, 2)
	self.checkerChannel = make(chan aucoalesce.Event)

	for _, rule := range gBannedRules {
		watcherRule, err := parseRule(rule)
		if err != nil {
			return fmt.Errorf("failed to parse built-in banned rule `%s': %w",
				rule, err)
		}

		self.bannedRules[watcherRule.rule] = watcherRule
	}

	status, err := self.commandClient.GetStatus()
	if err != nil {
		self.commandClient.Close()
		return err
	}

	if status.Enabled == 0 {
		err = self.commandClient.SetEnabled(true, libaudit.WaitForReply)
		if err != nil {
			self.commandClient.Close()
			return fmt.Errorf("failed to enable audit subsystem: %w", err)
		}
		self.logger.Info("audit: enabled kernel audit subsystem")
	}

	self.reassembler, err = libaudit.NewReassembler(5, 500*time.Millisecond, self)
	if err != nil {
		self.commandClient.Close()
		return err
	}

	self.logger.Info("audit: starting audit service")
	self.running = true

	// This is a workaround for errgroup not returning a cancel func or
	// exporting the one it keeps for itself.  The choice is to either
	// reimplement errgroup with an exported cancel func or just
	// use the hierarchical nature of context cancelation to get the
	// same result.  The only difference is that we need to wait for
	// either context to signal Done.
	ctx, cancel := context.WithCancel(context.Background())
	grp, grpctx := errgroup.WithContext(ctx)

	options := api.QueueOptions{
		DisableFileBuffering: false,
		FileBufferLeaseSize:  4096,
		OwnerName:            "audit-plugin",
	}

	self.messageQueue, err = directory.NewListenerBytes(self.config, grpctx, options.OwnerName,
		options)
	if err != nil {
		cancel()
		self.commandClient.Close()
		self.running = false
		return err
	}

	// Start up the workers
	grp.Go(func() error { return self.logEventLoop(grpctx) })
	grp.Go(func() error { return self.startMaintainer(grpctx) })
	grp.Go(func() error { return self.startRulesChecker(grpctx) })
	grp.Go(func() error { return self.mainEventLoop(grpctx) })
	grp.Go(func() error { return self.listenerEventLoop(grpctx) })
	grp.Go(func() error { return self.reportStats(grpctx) })

	// Wait until we cancel the context or something hits an error
	go func() {
		self.Debug("audit: shutdown watcher starting")
		defer self.Debug("audit: shutdown watcher exited")

		select {
		// If we exit the main event loop normally
		case <-ctx.Done():
			break
		// If any of the goroutines exits abnormally
		case <-grpctx.Done():
			break
		}

		err := grp.Wait()
		if !errors.Is(err, context.Canceled) {
			self.logger.Info("audit: shutting down due to error ; err=%s", err)
		}

		self.shutdown()
	}()

	self.cancelService = cancel
	self.serviceWg.Add(1)
	return nil
}

func (self *auditService) shutdown() {
	// If we're shutting down due to error, we'll still have subscribed callers
	self.subscriberLock.Lock()
	for _, subscriber := range self.subscribers {
		self.unsubscribe(subscriber, true)
	}
	self.subscribers = []*subscriber{}
	self.subscriberLock.Unlock()

	self.reassembler.Close()
	self.commandClient.Close()

	close(self.logChannel)
	close(self.checkerChannel)

	self.bannedRules = map[string]*AuditRule{}
	self.rules = map[string]*RefcountedAuditRule{}

	self.logger.Info("audit: Shut down audit service")

	self.serviceLock.Lock()
	self.running = false
	self.shuttingDown = false
	self.serviceWg.Done()
	self.serviceLock.Unlock()
}

func (self *auditService) acceptEvents(ctx context.Context) error {
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
			self.rawBufPool.Put(buf)
			if errors.Is(err, syscall.EAGAIN) {
				continue
			}
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
		self.messageQueue.Send(buf)
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

func (self *auditService) processOneMessage(buf []byte) error {
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

	self.reassembler.PushMessage(msgBuf)

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

func (self *auditService) mainEventLoop(ctx context.Context) error {
	self.Debug("audit: mainEventLoop started")
	defer self.Debug("audit: mainEventLoop exited")
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case buf, ok := <-self.messageQueue.Output():
			if !ok {
				return nil
			}
			err := self.processOneMessage(buf.Data())
			if err != nil {
				self.logger.Info("failed to parse message: %v", err)
			}
			buf.Put()
			self.currentMessagesQueuedCounter.Dec()
		}
	}
}

func (self *auditService) logEventLoop(ctx context.Context) error {
	self.Debug("audit: log event loop started")
	defer self.Debug("audit: log event loop exited")
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-self.logChannel:
			if !ok {
				fmt.Printf("log channel closed\n")
				return nil
			}

			self.subscriberLock.Lock()
			for _, subscriber := range self.subscribers {
				subscriber.logChannel <- msg
			}
			self.subscriberLock.Unlock()
			self.logger.Info(msg)
		}
	}

	return nil
}

func (self *auditService) listenerEventLoop(ctx context.Context) error {
	defer self.messageQueue.Close()
	self.Debug("audit: listener event loop started")
	defer self.Debug("audit: listener event loop exited")

	err := self.listener.Open(ctx)
	if err != nil {
		return err
	}
	defer self.listener.Close()

	for {
		err = self.listener.Wait(ctx)
		if err != nil {
			return err
		}

		self.totalReceiveLoopCounter.Inc()
		err = self.acceptEvents(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}

			self.logChannel <- fmt.Sprintf("audit: acceptEvents %v", err)
			return err
		}
	}
}

func (self *auditService) reportStats(ctx context.Context) error {
	lastReceived := 0
	lastDiscarded := 0
	lastDropped := 0
	lastQueued := 0
	lastPosted := 0
	lastMessagesPosted := 0

	if !gDebugPrintingEnabled {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
			break
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

	return nil
}

func (self *auditService) startMaintainer(ctx context.Context) error {
	self.Debug("audit: reassembler maintainer started")
	defer self.Debug("audit: reassembler maintainer exited")

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(gReassemblerMaintainerTimeout):
			// Maintain will only return error when closed
			if self.reassembler.Maintain() != nil {
				return nil
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

	self.totalRowsPostedCounter.Inc()
	self.subscriberLock.RLock()
	for _, subscriber := range self.subscribers {
		subscriber.eventChannel <- *event
	}
	self.subscriberLock.RUnlock()
}

func (self *auditService) EventsLost(count int) {
	if count > 0x80000000 {
		count = 0x100000000 - count
	}
	self.logChannel <- fmt.Sprintf("Detected the loss of %v sequences.", count)
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

func (self *auditService) notifyMissingRule(rule *AuditRule) {
	self.subscriberLock.Lock()
	defer self.subscriberLock.Lock()
	count := 0

	msg := fmt.Sprintf("audit: replaced missing rule `%v'", rule.rule)
	for _, subscriber := range self.subscribers {
		_, ok := subscriber.rules[rule.rule]
		if ok {
			subscriber.logChannel <- msg
			count += 1
		}
	}

	if count > 0 {
		self.logger.Info("audit: replaced missing rule `%v'", rule.rule)
	}
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
		self.logChannel <- fmt.Sprintf("audit: removed banned rule %v", text)
	}

	return nil
}

// This will allow us to treat a series of rule changes as a single event.  Otherwise, we'll
// end up checking the rules for _every_ event, which is just wasteful.
func (self *auditService) startRulesChecker(ctx context.Context) error {
	self.Debug("audit: rules checker started")
	defer self.Debug("audit: rules checker exited")

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(gBatchTimeout):
			err := self.checkRules()
			if err != nil {
				self.logger.Warn("audit: rules check failed %v", err)
			}
		case <-self.checkerChannel:
			// Reset timer
			break
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

func (self *auditService) unsubscribe(subscriber *subscriber, shuttingDown bool) {
	// Not an error; Shutdown and caller-initiated unsubscribe can happen
	// concurrently.  Both will take the subscriberLock.
	if !subscriber.subscribed {
		return
	}

	for i, sub := range self.subscribers {
		if sub != subscriber {
			continue
		}

		newlen := len(self.subscribers) - 1
		self.subscribers[i] = self.subscribers[newlen]
		self.subscribers = self.subscribers[:newlen]
		break
	}

	self.Debug("audit: removing subscriber, total now %v", len(self.subscribers))

	_ = self.removeSubscriberRules(subscriber)

	subscriber.disconnect()

	if !shuttingDown {
		self.serviceLock.Lock()
		// No more subscribers: Shut it down
		if len(self.subscribers) == 0 {
			self.shuttingDown = true
			self.cancelService()
		}
		self.serviceLock.Unlock()
	}
}

func (self *auditService) Subscribe(rules []string) (AuditEventSubscriber, error) {
	subscriber := newSubscriber()

	err := subscriber.addRules(rules)
	if err != nil {
		return nil, err
	}

	err = self.runService()
	if err != nil {
		return nil, err
	}

	defer self.subscriberLock.Unlock()
	self.subscriberLock.Lock()

	self.subscribers = append(self.subscribers, subscriber)
	self.Debug("audit: adding subscriber, total now %v", len(self.subscribers))
	err = self.addSubscriberRules(subscriber)
	if err != nil {
		self.unsubscribe(subscriber, false)
		return nil, err
	}

	return subscriber, nil
}

func (self *auditService) Unsubscribe(auditSubscriber AuditEventSubscriber) {
	defer self.subscriberLock.Unlock()
	self.subscriberLock.Lock()

	subscriber := auditSubscriber.(*subscriber)
	self.unsubscribe(subscriber, false)
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
		client, err := libaudit.NewAuditClient(nil)
		if err != nil {
			return nil, err
		}

		listener := NewAuditListener()
		gService = newAuditService(config_obj, logger, listener, client)
	}

	return AuditService(gService), nil
}
