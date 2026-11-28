package event

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type userCreated struct{ ID string }

type namer interface{ Name() string }

func TestBroker_ZeroValue(t *testing.T) {
	var broker Broker
	broker.RegisterBus(NewBus[userCreated]())
	if err := broker.Publish(t.Context(), userCreated{}); err != nil {
		t.Fatal(err)
	}
}

func TestBroker_RoutesByType(t *testing.T) {
	ctx := context.Background()
	b := NewBroker()
	bus := NewBus[userCreated]()
	b.RegisterBus(bus)

	var got []string
	bus.Subscribe(func(_ context.Context, e userCreated) error {
		got = append(got, e.ID)
		return nil
	})
	bus.Subscribe(func(context.Context, userCreated) error { return errors.New("boom") })

	if err := b.Publish(ctx, userCreated{ID: "1"}); err == nil || err.Error() != "boom" {
		t.Errorf("Publish error = %v, want boom", err)
	}
	if len(got) != 1 || got[0] != "1" {
		t.Errorf("handler got %v", got)
	}

	if err := b.Publish(ctx, &userCreated{}); err == nil {
		t.Error("expected error for unregistered pointer type")
	}
	if err := b.Publish(ctx, nil); err == nil {
		t.Error("expected error for nil event")
	}
	if err := bus.Publish(ctx, "wrong"); err == nil {
		t.Error("expected error for wrong event type")
	}
}

type publisherWithTypeHook struct {
	Publisher
	beforeType func()
}

func (p publisherWithTypeHook) Type() reflect.Type {
	p.beforeType()
	return p.Publisher.Type()
}

func TestBroker_RegisterBusTypeCanPublish(t *testing.T) {
	ctx := t.Context()
	broker := NewBroker()
	broker.RegisterBus(NewBus[string]())

	var publishErr error
	bus := NewBus[userCreated]()
	done := make(chan struct{})
	go func() {
		broker.RegisterBus(publisherWithTypeHook{
			Publisher: bus,
			beforeType: func() {
				publishErr = broker.Publish(ctx, "ready")
			},
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RegisterBus blocked when Publisher.Type called Publish")
	}
	if publishErr != nil {
		t.Fatalf("Publish in Publisher.Type returned %v", publishErr)
	}
	if err := broker.Publish(ctx, userCreated{}); err != nil {
		t.Errorf("Publish after registration returned %v", err)
	}
}

func TestBus_InterfaceTypeDoesNotPanic(t *testing.T) {
	if got := NewBus[namer]().Type().String(); got != "event.namer" {
		t.Errorf("Type() = %s", got)
	}
}

func TestBus_PublishNilInterface(t *testing.T) {
	bus := NewBus[namer]()
	handlerErr := errors.New("handler called")
	bus.Subscribe(func(_ context.Context, event namer) error {
		if event != nil {
			t.Errorf("handler got %v, want nil", event)
		}
		return handlerErr
	})

	var event namer
	if err := bus.Publish(t.Context(), event); !errors.Is(err, handlerErr) {
		t.Errorf("Publish returned %v, want %v", err, handlerErr)
	}
	if err := NewBus[userCreated]().Publish(t.Context(), nil); err == nil {
		t.Error("expected error for nil event on a concrete bus")
	}
}

func TestBus_ZeroValueRunsAsyncHandlers(t *testing.T) {
	var bus Bus[userCreated]
	var got string
	bus.SubscribeAsync(func(_ context.Context, e userCreated) error {
		got = e.ID
		return nil
	})

	if err := bus.Publish(t.Context(), userCreated{ID: "1"}); err != nil {
		t.Fatal(err)
	}
	bus.Wait()
	if got != "1" {
		t.Errorf("async handler got ID %q, want %q", got, "1")
	}
}

func TestBus_AsyncSurvivesCancelledContext(t *testing.T) {
	bus := NewBus[userCreated]()
	done := make(chan error, 1)
	bus.SubscribeAsync(func(ctx context.Context, _ userCreated) error {
		done <- ctx.Err()
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bus.Publish(ctx, userCreated{}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("async handler saw ctx error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("async handler did not run")
	}
}

func TestBus_AsyncWrapperCanPublish(t *testing.T) {
	bus := NewBus[userCreated]()
	ctx := t.Context()
	var publishErr error
	if err := bus.SetAsyncHandler(func(h Handler[userCreated]) Handler[userCreated] {
		publishErr = bus.Publish(ctx, userCreated{})
		return h
	}); err != nil {
		t.Fatal(err)
	}

	handlerErr := errors.New("handler called")
	done := make(chan struct{})
	go func() {
		bus.SubscribeAsync(func(context.Context, userCreated) error { return handlerErr })
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SubscribeAsync blocked when the wrapper called Publish")
	}
	if publishErr != nil {
		t.Fatalf("Publish in wrapper returned %v", publishErr)
	}
	if err := bus.Publish(ctx, userCreated{}); !errors.Is(err, handlerErr) {
		t.Errorf("Publish after subscription returned %v, want %v", err, handlerErr)
	}
}

func TestBus_WaitForAsyncHandlers(t *testing.T) {
	bus := NewBus[userCreated]()
	var done bool
	bus.SubscribeAsync(func(context.Context, userCreated) error {
		time.Sleep(50 * time.Millisecond)
		done = true
		return nil
	})

	if err := bus.Publish(context.Background(), userCreated{}); err != nil {
		t.Fatal(err)
	}
	bus.Wait()
	if !done {
		t.Error("Wait returned before the async handler finished")
	}
}
