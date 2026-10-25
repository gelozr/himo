// Package event provides typed in-process event buses and a Broker that routes events by type.
package event

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
)

// Handler handles one event of type T.
type Handler[T any] func(context.Context, T) error

// Bus delivers events of type T to its subscribers. It is safe for concurrent use.
type Bus[T any] struct {
	mu           sync.RWMutex
	handlers     []Handler[T]
	asyncHandler func(Handler[T]) Handler[T]
	async        sync.WaitGroup
}

// NewBus creates a Bus whose async handlers run in their own goroutine.
func NewBus[T any]() *Bus[T] {
	b := &Bus[T]{}
	b.asyncHandler = b.goHandler
	return b
}

// Subscribe adds h; Publish runs it synchronously and returns its error.
func (b *Bus[T]) Subscribe(h Handler[T]) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = append(b.handlers, h)
}

// SubscribeAsync subscribes h to run in the background. Its errors and panics are logged
// with slog's default logger, not returned by Publish.
func (b *Bus[T]) SubscribeAsync(h Handler[T]) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = append(b.handlers, b.asyncHandler(h))
}

// SetAsyncHandler replaces how SubscribeAsync wraps handlers (e.g. a worker pool,
// or a synchronous wrapper in tests). It only affects later subscriptions.
func (b *Bus[T]) SetAsyncHandler(ah func(Handler[T]) Handler[T]) error {
	if ah == nil {
		return errors.New("nil async handler")
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.asyncHandler = ah

	return nil
}

// Publish runs every handler in subscription order and joins their errors.
func (b *Bus[T]) Publish(ctx context.Context, evt any) error {
	e, ok := evt.(T)
	if !ok {
		return fmt.Errorf("invalid event type: %T", evt)
	}

	// No copy needed: handlers are only ever appended, which never writes inside this slice's length.
	b.mu.RLock()
	handlers := b.handlers
	b.mu.RUnlock()

	var errs []error
	for _, handle := range handlers {
		if err := handle(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Wait blocks until the async handlers started so far have returned. Call it on shutdown.
// It doesn't track handlers wrapped by a custom SetAsyncHandler.
func (b *Bus[T]) Wait() {
	b.async.Wait()
}

// Type is the event type the bus accepts; Broker routes on it.
func (b *Bus[T]) Type() reflect.Type {
	return reflect.TypeFor[T]()
}

func (b *Bus[T]) goHandler(h Handler[T]) Handler[T] {
	return func(ctx context.Context, evt T) error {
		// The publisher's ctx is often a request that ends before the handler does.
		ctx = context.WithoutCancel(ctx)
		b.async.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					slog.ErrorContext(ctx, "async event handler panicked", "event", fmt.Sprintf("%T", evt), "panic", r)
				}
			}()
			if err := h(ctx, evt); err != nil {
				slog.ErrorContext(ctx, "async event handler failed", "event", fmt.Sprintf("%T", evt), "err", err)
			}
		})
		return nil
	}
}
