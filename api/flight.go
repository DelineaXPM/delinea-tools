package api

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

// Cross-client grant coalescing. Per-client coalescing (c.granting) collapses
// one client's concurrent callers onto one grant; this layer collapses the
// per-client leaders themselves, so clients constructed per operation — the
// shape mechanical ports produce — cost one grant per credential under
// concurrency instead of one per client. The stakes are the failure case: a
// rotated credential under load becomes one failed authentication attempt
// per window rather than one per caller racing the account toward lockout.
//
// A flight is scoped to (token cache instance, credential key): exactly the
// clients that would share the completed grant through that cache share the
// in-flight one, so DisableCache clients and deliberately isolated caches
// never couple. The key's credential digest means every sharer holds the
// same URL, target, identity, secret, and grant-affecting header context.

// flightKey scopes a shared grant by the stable identity assigned to a
// pointer-valued cache. The type-and-address key avoids invoking equality or
// hashing on arbitrary caller implementations.
type flightKey struct {
	cacheID flightIdentity
	key     CacheKey
}

type flightIdentity struct {
	typeOf  reflect.Type
	pointer uintptr
}

func (id flightIdentity) valid() bool { return id.pointer != 0 }

// sharedGrant is one in-progress grant that per-client leaders coalesce
// onto, carrying the same outcome-sharing semantics as inflightGrant: a
// denial and a server transient are shared, and only a failure the leading
// client owns (leaderLocal — its own context, or its panic) makes a waiter
// take its own attempt.
type sharedGrant struct {
	done        chan struct{}
	gr          grantResponse
	err         error
	leaderLocal bool
	waiters     atomic.Int32 // observability and deterministic tests
}

var (
	sharedGrantsMu sync.Mutex
	sharedGrants   = map[flightKey]*sharedGrant{}
)

// cacheFlightID returns zero for value-valued implementations — even when the
// value's static type is comparable, an interface field can hold an
// unhashable dynamic value and panic during a map operation — and for
// pointers to zero-size types: every zero-size allocation shares one address,
// so two deliberately distinct instances of a zero-size cache would otherwise
// collapse into one flight identity and couple clients their construction
// meant to isolate.
func cacheFlightID(cache TokenCache) flightIdentity {
	if cache == nil {
		return flightIdentity{}
	}
	t := reflect.TypeOf(cache)
	if t.Kind() != reflect.Pointer || t.Elem().Size() == 0 {
		return flightIdentity{}
	}
	return flightIdentity{typeOf: t, pointer: reflect.ValueOf(cache).Pointer()}
}

// coalescedGrant performs the network grant through the cross-client flight
// for this client's cache and key, or directly when the client is not
// enrolled. It is called only from runGrant — the per-client leader — so
// each client contributes at most one participant per flight.
func (c *Client) coalescedGrant(ctx context.Context) (grantResponse, error) {
	if !c.flightID.valid() {
		return c.grant(ctx)
	}
	fk := flightKey{cacheID: c.flightID, key: c.key}
	for {
		sharedGrantsMu.Lock()
		if f, ok := sharedGrants[fk]; ok {
			f.waiters.Add(1)
			sharedGrantsMu.Unlock()
			select {
			case <-f.done:
				if f.err != nil && f.leaderLocal {
					continue
				}
				return f.gr, f.err
			case <-ctx.Done():
				return grantResponse{}, classifyTransport(ctx.Err())
			}
		}
		f := &sharedGrant{done: make(chan struct{})}
		sharedGrants[fk] = f
		sharedGrantsMu.Unlock()

		completed := false
		finish := func(gr grantResponse, err error, leaderLocal bool) {
			sharedGrantsMu.Lock()
			f.gr, f.err, f.leaderLocal = gr, err, leaderLocal
			delete(sharedGrants, fk)
			close(f.done)
			sharedGrantsMu.Unlock()
			completed = true
		}
		// The finalizer mirrors runGrant's: a panicking grant (an embedder's
		// Transport faulting) must not leave a registered flight whose channel
		// never closes, and it is the leader's own failure, so waiters retry.
		// The panic itself keeps propagating to runGrant's finalizer.
		defer func() {
			if !completed {
				finish(grantResponse{}, fmt.Errorf("%w: token grant aborted", ErrTransport), true)
			}
		}()
		gr, err := c.grant(ctx)
		if err != nil {
			finish(grantResponse{}, err, leaderLocalFailure(ctx.Err(), err))
			return grantResponse{}, err
		}
		finish(gr, nil, false)
		return gr, nil
	}
}
