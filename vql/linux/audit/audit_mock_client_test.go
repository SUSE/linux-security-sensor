package audit

import (
	"errors"
	"reflect"
	"syscall"

	libaudit "github.com/elastic/go-libaudit/v2"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/vfilter"
)

type mockCommandClient struct {
	status libaudit.AuditStatus
	rules  [][]byte
}

func newMockCommandClient() *mockCommandClient {
	return &mockCommandClient{
		status: libaudit.AuditStatus{},
		rules:  [][]byte{},
	}
}

func (self *mockCommandClient) AddRule(rule []byte) error {
	for _, currentRule := range self.rules {
		if reflect.DeepEqual(currentRule, rule) {
			return errors.New("rule exists")
		}
	}

	self.rules = append(self.rules, rule)
	return nil
}

func (self *mockCommandClient) DeleteRule(rule []byte) error {
	rules := [][]byte{}
	found := false
	for _, currentRule := range self.rules {
		if reflect.DeepEqual(currentRule, rule) {
			found = true
			break
		}
		rules = append(rules, currentRule)
	}
	if !found {
		return syscall.ENOENT
	}

	self.rules = rules
	return nil
}

func (self *mockCommandClient) GetRules() ([][]byte, error) {
	return self.rules, nil
}

func (self *mockCommandClient) GetStatus() (*libaudit.AuditStatus, error) {
	return &self.status, nil
}

func (self *mockCommandClient) SetEnabled(enabled bool, wm libaudit.WaitMode) error {
	var e uint32
	if enabled {
		e = 1
	}
	self.status.Enabled = e
	return nil
}

func (self *mockCommandClient) Close() error {
	self.rules = [][]byte{}
	return nil
}

type AuditTestSuite struct {
	test_utils.TestSuite

	client *mockCommandClient
	scope  vfilter.Scope
}

func (self *AuditTestSuite) SetupTest() {
	self.ConfigObj = self.LoadConfig()
	self.TestSuite.SetupTest()
}
