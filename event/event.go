package event

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
)

// Publisher is a bus the Broker can route events to.
type Publisher interface {
	Publish(ctx context.Context, event any) error
	Type() reflect.Type
}

// Broker routes each event to the bus registered for its concrete type.
// Buses for interface types never match, since events are routed by their dynamic type.
type Broker struct {
	mu    sync.RWMutex
	buses map[reflect.Type]Publisher
}

// NewBroker creates an empty Broker.
func NewBroker() *Broker {
	return &Broker{
		buses: make(map[reflect.Type]Publisher),
	}
}

// RegisterBus routes events of bus.Type() to bus, replacing any bus already registered for it.
func (r *Broker) RegisterBus(bus Publisher) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buses[bus.Type()] = bus
}

// Publish sends event to the bus registered for its dynamic type.
func (r *Broker) Publish(ctx context.Context, event any) error {
	if event == nil {
		return errors.New("event is nil")
	}

	t := reflect.TypeOf(event)

	r.mu.RLock()
	bus, ok := r.buses[t]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("event bus [%s] not found", t)
	}

	return bus.Publish(ctx, event)
}
