//go:build linux
// +build linux

package audit

import (
	"context"
	_ "embed"
	"encoding/json"
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
}

type TestListener struct {
	events [][]byte
	count  int
	ctx    context.Context
	cancel context.CancelFunc
}

func newTestListener() *TestListener {
	return &TestListener{}
}

//go:embed testdata.json
var eventsJson []byte

func (self *TestListener) Open(ctx context.Context) error {
	self.ctx, self.cancel = context.WithCancel(context.Background())
	//	fmt.Printf("%v\n", string(eventsJson))
	return json.Unmarshal(eventsJson, &self.events)
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
	listener := newTestListener()
	client := newMockCommandClient()
	self.auditService = newAuditService(self.ConfigObj, logger, listener, client)

	self.TestSuite.SetupTest()
}

func (self *AuditServiceTestSuite) TearDown() {
}

func (self *AuditServiceTestSuite) TestRunService() {
	self.auditService.runService()

	rules := []string{}

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

	goldie.Assert(self.T(), "TestRunService", golden)
}

func TestAuditService(t *testing.T) {
	suite.Run(t, &AuditServiceTestSuite{})
}
