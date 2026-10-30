package registry

import (
	"errors"
	"testing"
)

var errNotFound = errors.New("not found")

func TestRegistry(t *testing.T) {
	r := New[string, int](errNotFound)

	if !r.Add("a", 1) || !r.Add("b", 2) {
		t.Fatal("Add of new names failed")
	}
	if r.Add("a", 10) {
		t.Error("Add replaced an existing entry")
	}
	if got := r.Default(); got != 1 {
		t.Errorf("Default = %d, want the first entry added", got)
	}

	r.Set("a", 11)
	if got := r.MustGet("a"); got != 11 {
		t.Errorf("after Set, a = %d", got)
	}

	if err := r.SetDefault("missing"); !errors.Is(err, errNotFound) {
		t.Errorf("SetDefault(missing) = %v, want errNotFound", err)
	}
	if err := r.SetDefault("b"); err != nil || r.Default() != 2 {
		t.Errorf("SetDefault(b) = %v, Default = %d", err, r.Default())
	}

	if _, err := r.Get("missing"); !errors.Is(err, errNotFound) {
		t.Errorf("Get(missing) = %v, want errNotFound", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustGet(missing) did not panic")
		}
	}()
	r.MustGet("missing")
}

func TestRegistry_EmptyDefaultPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Default on an empty registry did not panic")
		}
	}()
	New[string, int](errNotFound).Default()
}

// Run with -race.
func TestRegistry_Concurrent(_ *testing.T) {
	r := New[string, int](errNotFound)
	r.Set("a", 1)
	r.Set("b", 2)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			r.Set("a", i)
			_ = r.SetDefault("b")
			_ = r.SetDefault("a")
		}
	}()
	for range 200 {
		_ = r.Default()
		_, _ = r.Get("b")
	}
	<-done
}
