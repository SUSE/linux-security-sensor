package audit

import (
	"fmt"
	"sync"

	auditrule "github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"www.velocidex.com/golang/vfilter"
)

type AuditRule struct {
	wfRule auditrule.WireFormat
	rule   string
}

func parseRule(rule string) (*AuditRule, error) {
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

	watcherRule := &AuditRule{
		wfRule: wfRule,
		rule:   normalizedRule,
	}

	return watcherRule, nil
}

type subscriber struct {
	eventChannel chan vfilter.Row
	logChannel   chan string
	rules        map[string]*AuditRule
	wait         sync.WaitGroup
	subscribed   bool
}

func newSubscriber() *subscriber {
	return &subscriber{
		eventChannel: make(chan vfilter.Row, 2),
		logChannel:   make(chan string, 2),
		rules:        map[string]*AuditRule{},
		wait:         sync.WaitGroup{},
		subscribed:   true,
	}
}

func (self *subscriber) Events() chan vfilter.Row {
	return self.eventChannel
}

func (self *subscriber) LogEvents() chan string {
	return self.logChannel
}

func (self *subscriber) addRules(rules []string) error {
	for _, line := range rules {
		parsedRule, err := parseRule(line)
		if err != nil {
			return err
		}

		_, ok := self.rules[parsedRule.rule]
		if ok {
			continue
		}

		self.rules[parsedRule.rule] = parsedRule
	}

	return nil
}

func (self *subscriber) disconnect() {
	if self.subscribed {
		close(self.eventChannel)
		close(self.logChannel)
	}

	self.subscribed = false
}
