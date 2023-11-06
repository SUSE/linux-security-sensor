//go:build linux
// +build linux

package audit

import (
	"context"
	_ "embed"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"syscall"
	"testing"

	"github.com/alecthomas/assert"
	"github.com/sebdah/goldie"
	"github.com/stretchr/testify/suite"

	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/vfilter"
)

type AuditServiceTestSuite struct {
	test_utils.TestSuite
	auditService *auditService
	listener     *TestListener
	client       *mockCommandClient
}

type TestListener struct {
	events      [][]byte
	count       int
	real_count  int
	ctx         context.Context
	cancel      context.CancelFunc
	opened      bool
	failOpen    bool
	failReceive bool
	failWait    bool
	failClose   bool
}

func newTestListener() *TestListener {
	return &TestListener{}
}

//go:embed testdata.json
var eventsJson []byte

func (self *TestListener) Open(ctx context.Context) error {
	if self.opened {
		return syscall.EBUSY
	}
	if self.failOpen {
		return syscall.EPERM
	}

	newctx, cancel := context.WithCancel(ctx)
	err := json.Unmarshal(eventsJson, &self.events)
	if err != nil {
		cancel()
		return nil
	}

	seqs := map[int]bool{}

	// Count the sequence numbers to determine how many events are in
	// the test input stream
	re := regexp.MustCompile(`\d+:(\d+)`)
	for _, line := range self.events {
		found := re.FindSubmatch(line[22:])
		if found != nil {
			seq, err := strconv.Atoi(string(found[1]))
			if err != nil {
				cancel()
				return err
			}
			seqs[seq] = true
		}
	}

	self.real_count = len(seqs)

	self.ctx = newctx
	self.cancel = cancel
	self.opened = true
	self.count = 0
	return nil
}

func (self *TestListener) Wait(ctx context.Context) error {
	if !self.opened || self.failWait {
		return syscall.ENOTCONN
	}
	return nil
}

func (self *TestListener) Receive(buf *auditBuf) error {
	if !self.opened || self.failReceive {
		return syscall.ENOTCONN
	}
	if self.count >= len(self.events) {
		self.cancel()
		return self.ctx.Err()
	}

	copy(buf.data, self.events[self.count])
	buf.size = len(self.events[self.count])

	self.count += 1
	return nil
}

func (self *TestListener) Close() error {
	if !self.opened || self.failClose {
		return syscall.ENOTCONN
	}
	self.cancel()
	self.cancel = nil
	self.opened = false
	return nil
}

func (self *AuditServiceTestSuite) SetupTest() {
	self.ConfigObj = self.LoadConfig()

	logger := logging.GetLogger(self.ConfigObj, &logging.ClientComponent)
	self.listener = newTestListener()
	self.client = newMockCommandClient()
	self.auditService = newAuditService(self.ConfigObj, logger, self.listener, self.client)

	self.TestSuite.SetupTest()
}

func (self *AuditServiceTestSuite) TearDownTest() {
	for {
		self.auditService.serviceLock.Lock()
		if !self.auditService.shuttingDown {
			self.auditService.serviceLock.Unlock()
			break
		}
		self.auditService.serviceLock.Unlock()
		self.auditService.serviceWg.Wait()
	}

	assert.False(self.T(), self.listener.opened, "self.listener.opened should be false")
	assert.False(self.T(), self.client.opened, "self.client.opened should be false")
	self.auditService = nil
	self.client = nil
	self.listener = nil
}

func (self *AuditServiceTestSuite) TestRunService() {
	err := self.auditService.runService()
	assert.NoError(self.T(), err)

	self.auditService.serviceLock.Lock()
	self.auditService.shuttingDown = true
	self.auditService.cancelService()
	self.auditService.serviceLock.Unlock()
}

func (self *AuditServiceTestSuite) TestRunServiceFailClientOpen() {
	self.client.failOpen = true
	err := self.auditService.runService()
	assert.Error(self.T(), err)
}

func (self *AuditServiceTestSuite) TestRunServiceFailListenerOpen() {
	self.listener.failOpen = true
	err := self.auditService.runService()
	assert.Error(self.T(), err)
}

func (self *AuditServiceTestSuite) TestSubscribeEvents() {
	rules := []string{"-a always,exit"}

	subscriber, err := self.auditService.Subscribe(rules)
	assert.NoError(self.T(), err)
	defer self.auditService.Unsubscribe(subscriber)

	events := []vfilter.Row{}

L:
	for {
		select {
		case _, ok := <-subscriber.LogEvents():
			if !ok {
				break L
			}
		case event, ok := <-subscriber.Events():
			if !ok {
				break L
			}

			events = append(events, event)
		}
	}

	golden, err := json.MarshalIndent(events, "", "  ")
	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(events), self.listener.real_count)

	goldie.Assert(self.T(), "TestSubscribeEvents", golden)
}

func (self *AuditServiceTestSuite) TestSubscribeEventsListenerWaitFail() {
	rules := []string{"-a always,exit"}

	self.listener.failWait = true

	subscriber, err := self.auditService.Subscribe(rules)
	assert.NoError(self.T(), err)
	defer self.auditService.Unsubscribe(subscriber)

	events := []vfilter.Row{}

L:
	for {
		select {
		case _, ok := <-subscriber.LogEvents():
			if !ok {
				break L
			}
		case event, ok := <-subscriber.Events():
			if !ok {
				break L
			}

			events = append(events, event)
		}
	}

	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(events), 0)
}

func (self *AuditServiceTestSuite) TestMissingRules() {
	rules := []string{"-a always,exit", "-w /etc/passwd -p rwxa -k passwd"}

	subscriber, err := self.auditService.Subscribe(rules)
	assert.NoError(self.T(), err)
	defer self.auditService.Unsubscribe(subscriber)

	oRules, err := self.client.GetRules()
	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(oRules), len(rules))

	oldrule := self.client.rules[1]

	self.client.rules = self.client.rules[0:1]

	nRules, err := self.client.GetRules()
	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(nRules), 1)

	err = self.auditService.checkRules()
	assert.NoError(self.T(), err)

	nRules, err = self.client.GetRules()
	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(nRules), len(rules))

	assert.True(self.T(), reflect.DeepEqual(oldrule, self.client.rules[1]))

	events := []vfilter.Row{}

	logEvents := []string{}
L:
	for {
		select {
		case logEvent, ok := <-subscriber.LogEvents():
			if !ok {
				break L
			}
			logEvents = append(logEvents, logEvent)
		case event, ok := <-subscriber.Events():
			if !ok {
				break L
			}

			events = append(events, event)
		}
	}

	assert.NoError(self.T(), err)
	assert.Equal(self.T(), len(events), self.listener.real_count)
	assert.Equal(self.T(), len(logEvents), 1)
}

func (self *AuditServiceTestSuite) TestServiceRestart() {
	self.TestRunService()
	self.TestRunService()
	self.TestRunService()
}

func TestAuditService(t *testing.T) {
	suite.Run(t, &AuditServiceTestSuite{})
}
