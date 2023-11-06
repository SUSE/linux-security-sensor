//go:build linux
// +build linux

package audit

import (
	"context"
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"testing"

	_ "fmt"

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
}

type TestListener struct {
	events     [][]byte
	count      int
	real_count int
	ctx        context.Context
	cancel     context.CancelFunc
}

func newTestListener() *TestListener {
	return &TestListener{}
}

//go:embed testdata.json
var eventsJson []byte

func (self *TestListener) Open(ctx context.Context) error {
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
	self.count = 0
	return nil
}

func (self *TestListener) Wait(ctx context.Context) error {
	return nil
}

func (self *TestListener) Receive(buf *auditBuf) error {
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
	self.cancel()
	return nil
}

func (self *AuditServiceTestSuite) SetupTest() {
	self.ConfigObj = self.LoadConfig()

	logger := logging.GetLogger(self.ConfigObj, &logging.ClientComponent)
	self.listener = newTestListener()
	client := newMockCommandClient()
	self.auditService = newAuditService(self.ConfigObj, logger, self.listener, client)

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

	self.auditService = nil
}

func (self *AuditServiceTestSuite) TestRunService() {
	err := self.auditService.runService()
	assert.NoError(self.T(), err)
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

func TestAuditService(t *testing.T) {
	suite.Run(t, &AuditServiceTestSuite{})
}
