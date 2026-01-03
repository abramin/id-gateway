package testutil

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"credo/pkg/platform/sentinel"
)

// ConcurrentResult tracks outcomes of concurrent test operations.
type ConcurrentResult struct {
	Successes int32
	Errors    int32
	Conflicts int32
	NotFounds int32
}

// Total returns the total number of operations executed.
func (r *ConcurrentResult) Total() int32 {
	return r.Successes + r.Errors + r.Conflicts + r.NotFounds
}

// RunConcurrent executes fn in parallel goroutines and collects results.
// The function categorizes errors into success, conflict, not_found, or generic error.
// This helper replaces the common pattern of WaitGroup + atomic counters in tests.
func RunConcurrent(goroutines int, fn func(idx int) error) *ConcurrentResult {
	var wg sync.WaitGroup
	var successes, errs, conflicts, notFounds atomic.Int32

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			err := fn(idx)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, sentinel.ErrConflict):
				conflicts.Add(1)
			case errors.Is(err, sentinel.ErrNotFound):
				notFounds.Add(1)
			default:
				errs.Add(1)
			}
		}(i)
	}

	wg.Wait()

	return &ConcurrentResult{
		Successes: successes.Load(),
		Errors:    errs.Load(),
		Conflicts: conflicts.Load(),
		NotFounds: notFounds.Load(),
	}
}

// RunConcurrentCtx executes fn in parallel goroutines with context support.
// Useful for tests that need timeout or cancellation handling.
func RunConcurrentCtx(ctx context.Context, goroutines int, fn func(ctx context.Context, idx int) error) *ConcurrentResult {
	return RunConcurrent(goroutines, func(idx int) error {
		return fn(ctx, idx)
	})
}

// RunConcurrentCollect executes fn in parallel and collects all errors.
// Use this when you need to inspect individual error types beyond the standard categories.
func RunConcurrentCollect(goroutines int, fn func(idx int) error) (successes int32, errs []error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successCount atomic.Int32
	collectedErrs := make([]error, 0)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := fn(idx); err != nil {
				mu.Lock()
				collectedErrs = append(collectedErrs, err)
				mu.Unlock()
			} else {
				successCount.Add(1)
			}
		}(i)
	}

	wg.Wait()
	return successCount.Load(), collectedErrs
}
