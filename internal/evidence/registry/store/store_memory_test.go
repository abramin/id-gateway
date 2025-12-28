package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/metrics"
	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
)

type InMemoryCacheSuite struct {
	suite.Suite
	cache *InMemoryCache
}

func (s *InMemoryCacheSuite) SetupTest() {
	s.cache = NewInMemoryCache(5 * time.Minute)
}

func TestInMemoryCacheSuite(t *testing.T) {
	suite.Run(t, new(InMemoryCacheSuite))
}

func testNationalID(val string) id.NationalID {
	nid, _ := id.ParseNationalID(val)
	return nid
}

func (s *InMemoryCacheSuite) TestSaveCitizen() {
	ctx := context.Background()
	key := testNationalID("ABC123456")

	s.Run("saves citizen record successfully", func() {
		record := &models.CitizenRecord{
			NationalID:  "ABC123456",
			FullName:    "Test User",
			DateOfBirth: "1990-01-01",
			Address:     "123 Test St",
			Valid:       true,
			CheckedAt:   time.Now(),
		}

		err := s.cache.SaveCitizen(ctx, key, record, false)
		s.Require().NoError(err)

		found, err := s.cache.FindCitizen(ctx, key, false)
		s.Require().NoError(err)
		s.Equal(record.NationalID, found.NationalID)
		s.Equal(record.FullName, found.FullName)
	})

	s.Run("overwrites existing citizen record with same key", func() {
		record1 := &models.CitizenRecord{NationalID: "ABC123456", FullName: "User One", Valid: true, CheckedAt: time.Now()}
		record2 := &models.CitizenRecord{NationalID: "ABC123456", FullName: "User Two", Valid: false, CheckedAt: time.Now()}

		_ = s.cache.SaveCitizen(ctx, key, record1, false)
		_ = s.cache.SaveCitizen(ctx, key, record2, false)

		found, err := s.cache.FindCitizen(ctx, key, false)
		s.Require().NoError(err)
		s.Equal("User Two", found.FullName)
		s.False(found.Valid)
	})

	s.Run("handles nil record gracefully", func() {
		err := s.cache.SaveCitizen(ctx, key, nil, false)
		s.NoError(err)
	})

	s.Run("rejects nil key", func() {
		record := &models.CitizenRecord{NationalID: "ABC123456", Valid: true, CheckedAt: time.Now()}
		err := s.cache.SaveCitizen(ctx, id.NationalID{}, record, false)
		s.Error(err)
	})

	s.Run("uses key parameter not record NationalID for cache key", func() {
		// This tests the fix for cache key collision in regulated mode
		key1 := testNationalID("KEY123")
		key2 := testNationalID("KEY456")

		// Both records have empty NationalID (simulating regulated/minimized mode)
		record1 := &models.CitizenRecord{NationalID: "", FullName: "", Valid: true, CheckedAt: time.Now()}
		record2 := &models.CitizenRecord{NationalID: "", FullName: "", Valid: false, CheckedAt: time.Now()}

		_ = s.cache.SaveCitizen(ctx, key1, record1, true)
		_ = s.cache.SaveCitizen(ctx, key2, record2, true)

		// Should be able to retrieve both separately
		found1, err1 := s.cache.FindCitizen(ctx, key1, true)
		found2, err2 := s.cache.FindCitizen(ctx, key2, true)

		s.Require().NoError(err1)
		s.Require().NoError(err2)
		s.True(found1.Valid)  // First record
		s.False(found2.Valid) // Second record - different!
	})

	s.Run("handles concurrent saves without race conditions", func() {
		cache := NewInMemoryCache(5 * time.Minute)
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				k := testNationalID("CONCURRENT" + string(rune('A'+idx%26)))
				r := &models.CitizenRecord{NationalID: k.String(), Valid: true, CheckedAt: time.Now()}
				_ = cache.SaveCitizen(ctx, k, r, false)
			}(i)
		}
		wg.Wait()
		citizens, sanctions := cache.Size()
		s.Equal(26, citizens)
		s.Equal(0, sanctions)
	})
}

func (s *InMemoryCacheSuite) TestFindCitizen() {
	ctx := context.Background()
	key := testNationalID("ABC123456")

	s.Run("returns citizen record when found and not expired", func() {
		record := &models.CitizenRecord{
			NationalID: "ABC123456",
			FullName:   "Test User",
			Valid:      true,
			CheckedAt:  time.Now(),
		}
		_ = s.cache.SaveCitizen(ctx, key, record, false)

		found, err := s.cache.FindCitizen(ctx, key, false)
		s.Require().NoError(err)
		s.Equal(record.NationalID, found.NationalID)
		s.Equal(record.FullName, found.FullName)
	})

	s.Run("returns ErrNotFound when record does not exist", func() {
		nonExistent := testNationalID("NONEXISTENT")
		_, err := s.cache.FindCitizen(ctx, nonExistent, false)
		s.ErrorIs(err, ErrNotFound)
	})

	s.Run("returns ErrNotFound when record is expired", func() {
		// Use a very short TTL cache
		shortCache := NewInMemoryCache(10 * time.Millisecond)
		record := &models.CitizenRecord{NationalID: "ABC123456", Valid: true, CheckedAt: time.Now()}
		start := time.Now()
		_ = shortCache.SaveCitizen(ctx, key, record, false)

		s.Require().Eventually(func() bool {
			return time.Since(start) >= 15*time.Millisecond
		}, 200*time.Millisecond, 5*time.Millisecond)

		_, err := shortCache.FindCitizen(ctx, key, false)
		s.ErrorIs(err, ErrNotFound)
	})

	s.Run("returns ErrNotFound when regulated mode does not match", func() {
		record := &models.CitizenRecord{NationalID: "ABC123456", Valid: true, CheckedAt: time.Now()}
		_ = s.cache.SaveCitizen(ctx, key, record, false) // saved as non-regulated

		_, err := s.cache.FindCitizen(ctx, key, true) // looking for regulated
		s.ErrorIs(err, ErrNotFound)
	})

	s.Run("handles concurrent reads without race conditions", func() {
		cache := NewInMemoryCache(5 * time.Minute)
		record := &models.CitizenRecord{NationalID: "ABC123456", Valid: true, CheckedAt: time.Now()}
		_ = cache.SaveCitizen(ctx, key, record, false)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = cache.FindCitizen(ctx, key, false)
			}()
		}
		wg.Wait()
		_, err := cache.FindCitizen(ctx, key, false)
		s.NoError(err)
	})
}

func (s *InMemoryCacheSuite) TestSaveSanction() {
	ctx := context.Background()
	key := testNationalID("ABC123456")

	s.Run("saves sanction record successfully", func() {
		record := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     true,
			Source:     "test-source",
			CheckedAt:  time.Now(),
		}

		err := s.cache.SaveSanction(ctx, key, record)
		s.Require().NoError(err)

		found, err := s.cache.FindSanction(ctx, key)
		s.Require().NoError(err)
		s.Equal(record.NationalID, found.NationalID)
		s.True(found.Listed)
	})

	s.Run("overwrites existing sanction record with same key", func() {
		record1 := &models.SanctionsRecord{NationalID: "ABC123456", Listed: false, CheckedAt: time.Now()}
		record2 := &models.SanctionsRecord{NationalID: "ABC123456", Listed: true, CheckedAt: time.Now()}

		_ = s.cache.SaveSanction(ctx, key, record1)
		_ = s.cache.SaveSanction(ctx, key, record2)

		found, err := s.cache.FindSanction(ctx, key)
		s.Require().NoError(err)
		s.True(found.Listed)
	})

	s.Run("handles nil record gracefully", func() {
		err := s.cache.SaveSanction(ctx, key, nil)
		s.NoError(err)
	})

	s.Run("rejects nil key", func() {
		record := &models.SanctionsRecord{NationalID: "ABC123456", Listed: true, CheckedAt: time.Now()}
		err := s.cache.SaveSanction(ctx, id.NationalID{}, record)
		s.Error(err)
	})

	s.Run("handles concurrent saves without race conditions", func() {
		cache := NewInMemoryCache(5 * time.Minute)
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				k := testNationalID("CONCURRENT" + string(rune('A'+idx%26)))
				r := &models.SanctionsRecord{NationalID: k.String(), Listed: true, CheckedAt: time.Now()}
				_ = cache.SaveSanction(ctx, k, r)
			}(i)
		}
		wg.Wait()
		citizens, sanctions := cache.Size()
		s.Equal(0, citizens)
		s.Equal(26, sanctions)
	})
}

func (s *InMemoryCacheSuite) TestFindSanction() {
	ctx := context.Background()
	key := testNationalID("ABC123456")

	s.Run("returns sanction record when found and not expired", func() {
		record := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     true,
			Source:     "test-source",
			CheckedAt:  time.Now(),
		}
		_ = s.cache.SaveSanction(ctx, key, record)

		found, err := s.cache.FindSanction(ctx, key)
		s.Require().NoError(err)
		s.Equal(record.NationalID, found.NationalID)
		s.True(found.Listed)
	})

	s.Run("returns ErrNotFound when record does not exist", func() {
		nonExistent := testNationalID("NONEXISTENT")
		_, err := s.cache.FindSanction(ctx, nonExistent)
		s.ErrorIs(err, ErrNotFound)
	})

	s.Run("returns ErrNotFound when record is expired", func() {
		shortCache := NewInMemoryCache(10 * time.Millisecond)
		record := &models.SanctionsRecord{NationalID: "ABC123456", Listed: true, CheckedAt: time.Now()}
		start := time.Now()
		_ = shortCache.SaveSanction(ctx, key, record)

		s.Require().Eventually(func() bool {
			return time.Since(start) >= 15*time.Millisecond
		}, 200*time.Millisecond, 5*time.Millisecond)

		_, err := shortCache.FindSanction(ctx, key)
		s.ErrorIs(err, ErrNotFound)
	})

	s.Run("handles concurrent reads without race conditions", func() {
		cache := NewInMemoryCache(5 * time.Minute)
		record := &models.SanctionsRecord{NationalID: "ABC123456", Listed: true, CheckedAt: time.Now()}
		_ = cache.SaveSanction(ctx, key, record)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = cache.FindSanction(ctx, key)
			}()
		}
		wg.Wait()
		_, err := cache.FindSanction(ctx, key)
		s.NoError(err)
	})
}

func (s *InMemoryCacheSuite) TestCacheSeparation() {
	ctx := context.Background()
	key := testNationalID("ABC123456")

	s.Run("citizen and sanction caches are independent", func() {
		citizenRecord := &models.CitizenRecord{NationalID: "ABC123456", FullName: "Citizen", Valid: true, CheckedAt: time.Now()}
		sanctionRecord := &models.SanctionsRecord{NationalID: "ABC123456", Listed: true, CheckedAt: time.Now()}

		_ = s.cache.SaveCitizen(ctx, key, citizenRecord, false)
		_ = s.cache.SaveSanction(ctx, key, sanctionRecord)

		foundCitizen, err1 := s.cache.FindCitizen(ctx, key, false)
		foundSanction, err2 := s.cache.FindSanction(ctx, key)

		s.Require().NoError(err1)
		s.Require().NoError(err2)
		s.Equal("Citizen", foundCitizen.FullName)
		s.True(foundSanction.Listed)
	})
}

func (s *InMemoryCacheSuite) TestEviction() {
	ctx := context.Background()

	// NationalID requires 6-20 chars, so use KEYABC1, KEYABC2, etc.
	makeKey := func(i int) id.NationalID {
		return testNationalID("KEYABC" + string(rune('0'+i)))
	}

	s.Run("evicts oldest citizen entry when at capacity", func() {
		cache := NewInMemoryCache(5*time.Minute, WithMaxSize(3))

		// Add 3 entries
		for i := 1; i <= 3; i++ {
			k := makeKey(i)
			r := &models.CitizenRecord{NationalID: k.String(), Valid: true, CheckedAt: time.Now()}
			_ = cache.SaveCitizen(ctx, k, r, false)
			time.Sleep(1 * time.Millisecond) // Ensure different timestamps
		}

		// Access KEYABC2 and KEYABC3 to make KEYABC1 the least recently accessed
		_, _ = cache.FindCitizen(ctx, makeKey(2), false)
		_, _ = cache.FindCitizen(ctx, makeKey(3), false)

		// Add a 4th entry - should evict KEYABC1
		k4 := makeKey(4)
		r4 := &models.CitizenRecord{NationalID: k4.String(), Valid: true, CheckedAt: time.Now()}
		_ = cache.SaveCitizen(ctx, k4, r4, false)

		// KEYABC1 should be evicted
		_, err := cache.FindCitizen(ctx, makeKey(1), false)
		s.ErrorIs(err, ErrNotFound)

		// KEYABC2, KEYABC3, KEYABC4 should still exist
		_, err2 := cache.FindCitizen(ctx, makeKey(2), false)
		_, err3 := cache.FindCitizen(ctx, makeKey(3), false)
		_, err4 := cache.FindCitizen(ctx, makeKey(4), false)
		s.NoError(err2)
		s.NoError(err3)
		s.NoError(err4)
	})

	s.Run("evicts oldest sanction entry when at capacity", func() {
		cache := NewInMemoryCache(5*time.Minute, WithMaxSize(3))

		// Add 3 entries
		for i := 1; i <= 3; i++ {
			k := makeKey(i)
			r := &models.SanctionsRecord{NationalID: k.String(), Listed: true, CheckedAt: time.Now()}
			_ = cache.SaveSanction(ctx, k, r)
			time.Sleep(1 * time.Millisecond)
		}

		// Access KEYABC2 and KEYABC3
		_, _ = cache.FindSanction(ctx, makeKey(2))
		_, _ = cache.FindSanction(ctx, makeKey(3))

		// Add a 4th entry
		k4 := makeKey(4)
		r4 := &models.SanctionsRecord{NationalID: k4.String(), Listed: true, CheckedAt: time.Now()}
		_ = cache.SaveSanction(ctx, k4, r4)

		// KEYABC1 should be evicted
		_, err := cache.FindSanction(ctx, makeKey(1))
		s.ErrorIs(err, ErrNotFound)
	})
}

func (s *InMemoryCacheSuite) TestErrNotFound() {
	s.Run("ErrNotFound is a sentinel error", func() {
		ctx := context.Background()
		nonExistent := testNationalID("NONEXISTENT")

		_, err := s.cache.FindCitizen(ctx, nonExistent, false)
		s.ErrorIs(err, ErrNotFound)
		s.Equal("not found", err.Error())
	})
}

func (s *InMemoryCacheSuite) TestClearAll() {
	ctx := context.Background()

	s.Run("removes all entries from both caches", func() {
		key1 := testNationalID("CITIZEN1")
		key2 := testNationalID("CITIZEN2")
		key3 := testNationalID("SANCTION1")

		citizenRecord1 := &models.CitizenRecord{NationalID: "CITIZEN1", Valid: true, CheckedAt: time.Now()}
		citizenRecord2 := &models.CitizenRecord{NationalID: "CITIZEN2", Valid: true, CheckedAt: time.Now()}
		sanctionRecord := &models.SanctionsRecord{NationalID: "SANCTION1", Listed: true, CheckedAt: time.Now()}

		_ = s.cache.SaveCitizen(ctx, key1, citizenRecord1, false)
		_ = s.cache.SaveCitizen(ctx, key2, citizenRecord2, false)
		_ = s.cache.SaveSanction(ctx, key3, sanctionRecord)

		// Verify entries exist
		citizens, sanctions := s.cache.Size()
		s.Equal(2, citizens)
		s.Equal(1, sanctions)

		// Clear all
		s.cache.ClearAll()

		// Verify all entries are gone
		citizens, sanctions = s.cache.Size()
		s.Equal(0, citizens)
		s.Equal(0, sanctions)

		// Verify lookups return ErrNotFound
		_, err1 := s.cache.FindCitizen(ctx, key1, false)
		_, err2 := s.cache.FindCitizen(ctx, key2, false)
		_, err3 := s.cache.FindSanction(ctx, key3)
		s.ErrorIs(err1, ErrNotFound)
		s.ErrorIs(err2, ErrNotFound)
		s.ErrorIs(err3, ErrNotFound)
	})

	s.Run("handles concurrent clears without race conditions", func() {
		cache := NewInMemoryCache(5 * time.Minute)
		key := testNationalID("CONCURRENT1")
		record := &models.CitizenRecord{NationalID: "CONCURRENT1", Valid: true, CheckedAt: time.Now()}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				_ = cache.SaveCitizen(ctx, key, record, false)
			}()
			go func() {
				defer wg.Done()
				cache.ClearAll()
			}()
		}
		wg.Wait()
		citizens, sanctions := cache.Size()
		s.LessOrEqual(citizens, 1)
		s.Equal(0, sanctions)
		s.NoError(cache.SaveCitizen(ctx, key, record, false))
		_, err := cache.FindCitizen(ctx, key, false)
		s.NoError(err)
	})

	s.Run("can add entries after clear", func() {
		key := testNationalID("AFTERCLEAR")
		record := &models.CitizenRecord{NationalID: "AFTERCLEAR", Valid: true, CheckedAt: time.Now()}

		s.cache.ClearAll()

		err := s.cache.SaveCitizen(ctx, key, record, false)
		s.Require().NoError(err)

		found, err := s.cache.FindCitizen(ctx, key, false)
		s.Require().NoError(err)
		s.Equal("AFTERCLEAR", found.NationalID)
	})
}

func (s *InMemoryCacheSuite) TestMetricsIntegration() {
	ctx := context.Background()

	s.Run("cache operations work without metrics configured", func() {
		// Default cache has no metrics - should not panic
		cache := NewInMemoryCache(5 * time.Minute)
		key := testNationalID("NOMETRICS")
		record := &models.CitizenRecord{NationalID: "NOMETRICS", Valid: true, CheckedAt: time.Now()}

		err := cache.SaveCitizen(ctx, key, record, false)
		s.Require().NoError(err)

		found, err := cache.FindCitizen(ctx, key, false)
		s.Require().NoError(err)
		s.Equal("NOMETRICS", found.NationalID)

		// Miss should also work
		_, err = cache.FindCitizen(ctx, testNationalID("MISSING1"), false)
		s.ErrorIs(err, ErrNotFound)

		// ClearAll should work without metrics
		cache.ClearAll()
	})
}

// TestMetricsWithRegistry tests cache with actual Prometheus metrics.
// This is a separate test function to avoid duplicate registration issues.
func TestCacheWithMetrics(t *testing.T) {
	ctx := context.Background()

	// Create metrics once for all subtests
	m := metrics.New()

	t.Run("cache operations with metrics record hits and misses", func(t *testing.T) {
		hitsBefore := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("citizen"))
		missesBefore := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))
		invalidationsBefore := testutil.ToFloat64(m.CacheInvalidationsTotal)

		cache := NewInMemoryCache(5*time.Minute, WithMetrics(m))
		key := testNationalID("WITHMETRICS")
		record := &models.CitizenRecord{NationalID: "WITHMETRICS", Valid: true, CheckedAt: time.Now()}

		// Save and find should record hit
		err := cache.SaveCitizen(ctx, key, record, false)
		if err != nil {
			t.Fatalf("SaveCitizen failed: %v", err)
		}

		found, err := cache.FindCitizen(ctx, key, false)
		if err != nil {
			t.Fatalf("FindCitizen failed: %v", err)
		}
		if found.NationalID != "WITHMETRICS" {
			t.Errorf("expected WITHMETRICS, got %s", found.NationalID)
		}

		// Miss should be recorded
		_, err = cache.FindCitizen(ctx, testNationalID("MISSING2"), false)
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}

		// ClearAll should record invalidation
		cache.ClearAll()

		hitsAfter := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("citizen"))
		missesAfter := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))
		invalidationsAfter := testutil.ToFloat64(m.CacheInvalidationsTotal)

		if hitsAfter != hitsBefore+1 {
			t.Errorf("expected citizen hits to increase by 1, got %v -> %v", hitsBefore, hitsAfter)
		}
		if missesAfter != missesBefore+1 {
			t.Errorf("expected citizen misses to increase by 1, got %v -> %v", missesBefore, missesAfter)
		}
		if invalidationsAfter != invalidationsBefore+1 {
			t.Errorf("expected invalidations to increase by 1, got %v -> %v", invalidationsBefore, invalidationsAfter)
		}
	})

	t.Run("sanctions cache metrics work correctly", func(t *testing.T) {
		hitsBefore := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("sanctions"))
		missesBefore := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("sanctions"))

		cache := NewInMemoryCache(5*time.Minute, WithMetrics(m))
		key := testNationalID("SANCTIONMET")
		record := &models.SanctionsRecord{NationalID: "SANCTIONMET", Listed: true, CheckedAt: time.Now()}

		// Save and find should record hit
		err := cache.SaveSanction(ctx, key, record)
		if err != nil {
			t.Fatalf("SaveSanction failed: %v", err)
		}

		found, err := cache.FindSanction(ctx, key)
		if err != nil {
			t.Fatalf("FindSanction failed: %v", err)
		}
		if !found.Listed {
			t.Error("expected Listed to be true")
		}

		// Miss should be recorded
		_, err = cache.FindSanction(ctx, testNationalID("MISSING3"))
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}

		hitsAfter := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("sanctions"))
		missesAfter := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("sanctions"))

		if hitsAfter != hitsBefore+1 {
			t.Errorf("expected sanctions hits to increase by 1, got %v -> %v", hitsBefore, hitsAfter)
		}
		if missesAfter != missesBefore+1 {
			t.Errorf("expected sanctions misses to increase by 1, got %v -> %v", missesBefore, missesAfter)
		}
	})

	t.Run("expired entries record as misses", func(t *testing.T) {
		cache := NewInMemoryCache(10*time.Millisecond, WithMetrics(m))
		key := testNationalID("EXPIRING1")
		record := &models.CitizenRecord{NationalID: "EXPIRING1", Valid: true, CheckedAt: time.Now()}
		start := time.Now()
		missesBefore := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))

		_ = cache.SaveCitizen(ctx, key, record, false)
		require.Eventually(t, func() bool {
			return time.Since(start) >= 15*time.Millisecond
		}, 200*time.Millisecond, 5*time.Millisecond)

		// Expired lookup should be a miss
		_, err := cache.FindCitizen(ctx, key, false)
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for expired entry, got %v", err)
		}
		missesAfter := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))
		if missesAfter != missesBefore+1 {
			t.Errorf("expected citizen misses to increase by 1, got %v -> %v", missesBefore, missesAfter)
		}
	})

	t.Run("regulated mode mismatch records as miss", func(t *testing.T) {
		missesBefore := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))

		cache := NewInMemoryCache(5*time.Minute, WithMetrics(m))
		key := testNationalID("REGULATED1")
		record := &models.CitizenRecord{NationalID: "REGULATED1", Valid: true, CheckedAt: time.Now()}

		// Save as non-regulated
		_ = cache.SaveCitizen(ctx, key, record, false)

		// Request as regulated - should be a miss
		_, err := cache.FindCitizen(ctx, key, true)
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for regulated mode mismatch, got %v", err)
		}
		missesAfter := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("citizen"))
		if missesAfter != missesBefore+1 {
			t.Errorf("expected citizen misses to increase by 1, got %v -> %v", missesBefore, missesAfter)
		}
	})
}
