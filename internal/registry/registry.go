// Package registry is a concurrency-safe set of named entries with a default,
// shared by the auth, hash and mail Managers.
package registry

import (
	"fmt"
	"sync"
)

// Registry maps names to entries. The first entry added becomes the default.
type Registry[K comparable, V any] struct {
	mu       sync.RWMutex
	items    map[K]V
	def      K
	notFound error
}

// New creates an empty Registry. Lookups of missing names return notFound wrapped with the name.
func New[K comparable, V any](notFound error) *Registry[K, V] {
	return &Registry[K, V]{items: make(map[K]V), notFound: notFound}
}

// Get returns the entry for name.
func (r *Registry[K, V]) Get(name K) (V, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.get(name)
}

// MustGet returns the entry for name and panics if there is none.
func (r *Registry[K, V]) MustGet(name K) V {
	v, err := r.Get(name)
	if err != nil {
		panic(err)
	}
	return v
}

// Default returns the default entry. It panics if the registry is empty.
func (r *Registry[K, V]) Default() V {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, err := r.get(r.def)
	if err != nil {
		panic(err)
	}
	return v
}

// Add stores v under name unless the name is taken, and reports whether it did.
func (r *Registry[K, V]) Add(name K, v V) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.items[name]; ok {
		return false
	}
	r.set(name, v)
	return true
}

// Set stores v under name, replacing any existing entry.
func (r *Registry[K, V]) Set(name K, v V) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.set(name, v)
}

// SetDefault makes name the default. The name must already be registered.
func (r *Registry[K, V]) SetDefault(name K) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.get(name); err != nil {
		return err
	}
	r.def = name
	return nil
}

func (r *Registry[K, V]) get(name K) (V, error) {
	if v, ok := r.items[name]; ok {
		return v, nil
	}
	var zero V
	return zero, fmt.Errorf("%w: %v", r.notFound, name)
}

func (r *Registry[K, V]) set(name K, v V) {
	if len(r.items) == 0 {
		r.def = name
	}
	r.items[name] = v
}
