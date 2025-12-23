package device

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		assertion func(t *testing.T, result string)
	}{
		{
			name:      "empty user agent returns unknown device",
			userAgent: "",
			assertion: func(t *testing.T, result string) {
				assert.Equal(t, "Unknown Device", result)
			},
		},
		{
			name:      "chrome on desktop",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			assertion: func(t *testing.T, result string) {
				// Then: result should contain browser, "on", and OS
				assert.Contains(t, result, "Chrome")
				assert.Contains(t, result, "on")
				assert.NotContains(t, result, "  ")
			},
		},
		{
			name:      "safari on iphone",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			assertion: func(t *testing.T, result string) {
				// Then: mobile device should include platform
				assert.Contains(t, result, "on")
				assert.Contains(t, result, "iPhone")
			},
		},
		{
			name:      "firefox on linux",
			userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			assertion: func(t *testing.T, result string) {
				// Then: desktop device with identifiable browser and OS
				assert.Contains(t, result, "Firefox")
				assert.Contains(t, result, "on")
			},
		},
		{
			name:      "unknown user agent returns formatted string",
			userAgent: "Unknown/1.0",
			assertion: func(t *testing.T, result string) {
				// Then: even unknown agents should be formatted with defaults
				assert.Contains(t, result, "on")
				assert.NotEmpty(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseUserAgent(tt.userAgent)
			tt.assertion(t, result)
		})
	}
}

func TestParseUserAgentFormatting(t *testing.T) {
	t.Run("result has no leading or trailing whitespace", func(t *testing.T) {
		userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
		result := ParseUserAgent(userAgent)
		assert.Equal(t, result, strings.TrimSpace(result))
	})
}

func TestDeviceBindingFingerprint(t *testing.T) {
	svc := NewService(true)

	t.Run("disabled returns empty fingerprint", func(t *testing.T) {
		disabled := NewService(false)
		fp := disabled.ComputeFingerprint("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0")
		assert.Empty(t, fp)
	})

	t.Run("same user agent yields deterministic fingerprint", func(t *testing.T) {
		ua := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

		fp1 := svc.ComputeFingerprint(ua)
		fp2 := svc.ComputeFingerprint(ua)

		assert.Equal(t, fp1, fp2)
		assert.Len(t, fp1, 64)
	})

	t.Run("minor version changes do not affect fingerprint", func(t *testing.T) {
		ua1 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36"
		ua2 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.224 Safari/537.36"

		fp1 := svc.ComputeFingerprint(ua1)
		fp2 := svc.ComputeFingerprint(ua2)

		assert.Equal(t, fp1, fp2)
	})

	t.Run("major version changes affect fingerprint", func(t *testing.T) {
		ua1 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		ua2 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

		fp1 := svc.ComputeFingerprint(ua1)
		fp2 := svc.ComputeFingerprint(ua2)

		assert.NotEqual(t, fp1, fp2)
	})
}

func TestFingerprintComparison(t *testing.T) {
	svc := NewService(true)

	t.Run("mismatch reports drift", func(t *testing.T) {
		matched, drift := svc.CompareFingerprints("a", "b")
		assert.False(t, matched)
		assert.True(t, drift)
	})

	t.Run("match reports no drift", func(t *testing.T) {
		matched, drift := svc.CompareFingerprints("abc", "abc")
		assert.True(t, matched)
		assert.False(t, drift)
	})
}
