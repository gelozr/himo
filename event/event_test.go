package event

import (
	"context"
	"errors"
	"testing"
	"time"
)

type userCreated struct{ ID string }

type namer interface{ Name() string }

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

func TestBus_InterfaceTypeDoesNotPanic(t *testing.T) {
	if got := NewBus[namer]().Type().String(); got != "event.namer" {
		t.Errorf("Type() = %s", got)
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
