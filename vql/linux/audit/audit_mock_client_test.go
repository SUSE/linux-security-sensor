//go:build linux
// +build linux

package audit

import (
	"errors"
	"reflect"
	"syscall"

	libaudit "github.com/elastic/go-libaudit/v2"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
)

type mockCommandClient struct {
	status         libaudit.AuditStatus
	rules          [][]byte
	opened         bool
	failOpen       bool
	failAddRule    bool
	failDeleteRule bool
	failGetRules   bool
	failGetStatus  bool
	failSetEnabled bool
	failClose      bool
}

func newMockCommandClient() *mockCommandClient {
	return &mockCommandClient{
		status: libaudit.AuditStatus{},
		rules:  [][]byte{},
	}
}

func (self *mockCommandClient) Open() error {
	if self.opened {
		return syscall.EBUSY
	}

	if self.failOpen {
		return syscall.EPERM
	}

	self.opened = true
	self.rules = [][]byte{}
	return nil
}

func (self *mockCommandClient) AddRule(rule []byte) error {
	if !self.opened || self.failAddRule {
		return syscall.ENOTCONN
	}
	for _, currentRule := range self.rules {
		if reflect.DeepEqual(currentRule, rule) {
			return errors.New("rule exists")
		}
	}

	self.rules = append(self.rules, rule)
	return nil
}

func (self *mockCommandClient) DeleteRule(rule []byte) error {
	if !self.opened || self.failDeleteRule {
		return syscall.ENOTCONN
	}
	rules := [][]byte{}
	found := false

	for _, currentRule := range self.rules {
		if !found && len(rule) == len(currentRule) &&
		   reflect.DeepEqual(currentRule, rule) {
			found = true
			continue
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
	if !self.opened || self.failGetRules {
		return nil, syscall.ENOTCONN
	}
	return self.rules, nil
}

func (self *mockCommandClient) GetStatus() (*libaudit.AuditStatus, error) {
	if !self.opened || self.failGetStatus {
		return nil, syscall.ENOTCONN
	}
	return &self.status, nil
}

func (self *mockCommandClient) SetEnabled(enabled bool, wm libaudit.WaitMode) error {
	if !self.opened || self.failSetEnabled {
		return syscall.ENOTCONN
	}
	var e uint32
	if enabled {
		e = 1
	}
	self.status.Enabled = e
	return nil
}

func (self *mockCommandClient) Close() error {
	if !self.opened || self.failClose {
		return syscall.ENOTCONN
	}
	self.opened = false
	return nil
}

type AuditTestSuite struct {
	test_utils.TestSuite
}

func (self *AuditTestSuite) SetupTest() {
	self.ConfigObj = self.LoadConfig()
	self.TestSuite.SetupTest()
}
