package audit

import (
	"fmt"
	"syscall"

	libaudit "github.com/elastic/go-libaudit/v2"
)

type realCommandClient struct {
	client *libaudit.AuditClient
}

var clientNotOpenErr = fmt.Errorf("audit client is not open: %w", syscall.ENOTCONN)

func (self *realCommandClient) Open() error {
	if self.client != nil {
		return fmt.Errorf("client already open: %w", syscall.EBUSY)
	}
	client, err := libaudit.NewAuditClient(nil)
	if err == nil {
		self.client = client
	}

	return err
}

func (self *realCommandClient) AddRule(rule []byte) error {
	if self.client == nil {
		return clientNotOpenErr
	}
	return self.client.AddRule(rule)
}

func (self *realCommandClient) DeleteRule(rule []byte) error {
	if self.client == nil {
		return clientNotOpenErr
	}
	return self.client.DeleteRule(rule)
}

func (self *realCommandClient) GetRules() ([][]byte, error) {
	if self.client == nil {
		return nil, clientNotOpenErr
	}
	return self.client.GetRules()
}

func (self *realCommandClient) GetStatus() (*libaudit.AuditStatus, error) {
	if self.client == nil {
		return nil, clientNotOpenErr
	}
	return self.client.GetStatus()
}

func (self *realCommandClient) SetEnabled(enabled bool, wm libaudit.WaitMode) error {
	if self.client == nil {
		return clientNotOpenErr
	}
	return self.client.SetEnabled(enabled, wm)
}

func (self *realCommandClient) Close() error {
	if self.client == nil {
		return clientNotOpenErr
	}
	err := self.client.Close()
	self.client = nil
	return err
}

func NewCommandClient() commandClient {
	return &realCommandClient{}
}
