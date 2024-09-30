//go:build linux

package bpf

import (
	"context"
	"sync"

	"www.velocidex.com/golang/vfilter"
)

var (
	once    sync.Once
	manager *Manager
)

type Publisher interface {
	// Start loads the BPF module and starts the goroutine that publishes events.
	// Implementations should block until the BPF module is loaded.
	Start()
	// Stop stops the publishing goroutine and unloads the BPF module.
	// Implementations should block until the BPF module is unloaded.
	Stop()
}

type Subscriber struct {
	EventCh chan vfilter.Row
	ErrorCh chan error
}

type Manager struct {
	mu          sync.Mutex
	subscribers map[string][]Subscriber
	publishers  map[string]Publisher
}

func GetManager() *Manager {
	once.Do(func() {
		manager = &Manager{
			subscribers: make(map[string][]Subscriber),
			publishers:  make(map[string]Publisher),
		}
	})

	return manager
}

func (m *Manager) Subscribe(name string, publisher Publisher) Subscriber {
	m.mu.Lock()
	defer m.mu.Unlock()

	subscriber := Subscriber{
		EventCh: make(chan vfilter.Row),
		ErrorCh: make(chan error),
	}

	subscribers := m.subscribers[name]
	subscribers = append(subscribers, subscriber)
	m.subscribers[name] = subscribers

	if len(subscribers) == 1 {
		publisher.Start()
		m.publishers[name] = publisher
	}

	return subscriber
}

func (m *Manager) Unsubscribe(name string, subscriber Subscriber) {
	m.mu.Lock()
	defer m.mu.Unlock()

	subscribers := m.subscribers[name]
	for i, sub := range subscribers {
		if sub == subscriber {
			newLen := len(subscribers) - 1
			subscribers[i] = subscribers[newLen]
			subscribers = subscribers[:newLen]
			break
		}
	}
	m.subscribers[name] = subscribers

	if len(subscribers) == 0 {
		m.publishers[name].Stop()
	}
}

func (m *Manager) PublishEvent(ctx context.Context, name string, event any) {
	for _, subscriber := range m.subscribers[name] {
		select {
		case <-ctx.Done():
			return
		case subscriber.EventCh <- event:
		}
	}
}

func (m *Manager) PublishError(ctx context.Context, name string, err error) {
	for _, subscriber := range m.subscribers[name] {
		select {
		case <-ctx.Done():
			return
		case subscriber.ErrorCh <- err:
		}
	}
}
