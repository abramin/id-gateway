package privacy

import (
	"testing"
)

func TestAnonymizeIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// IPv4 cases
		{
			name:     "ipv4 standard address",
			input:    "192.168.1.47",
			expected: "192.168.1.0",
		},
		{
			name:     "ipv4 with last octet zero",
			input:    "10.0.0.0",
			expected: "10.0.0.0",
		},
		{
			name:     "ipv4 with high last octet",
			input:    "172.16.50.255",
			expected: "172.16.50.0",
		},
		{
			name:     "ipv4 localhost",
			input:    "127.0.0.1",
			expected: "127.0.0.0",
		},

		// IPv6 cases
		{
			name:     "ipv6 full address",
			input:    "2001:db8:85a3:0000:0000:8a2e:0370:7334",
			expected: "2001:0db8:85a3::",
		},
		{
			name:     "ipv6 compressed address",
			input:    "2001:db8:85a3::8a2e:370:7334",
			expected: "2001:0db8:85a3::",
		},
		{
			name:     "ipv6 loopback",
			input:    "::1",
			expected: "0000:0000:0000::",
		},
		{
			name:     "ipv6 link-local",
			input:    "fe80::1",
			expected: "fe80:0000:0000::",
		},

		// Edge cases
		{
			name:     "empty string",
			input:    "",
			expected: "unknown",
		},
		{
			name:     "unknown value",
			input:    "unknown",
			expected: "unknown",
		},
		{
			name:     "invalid ip",
			input:    "not-an-ip",
			expected: "invalid",
		},
		{
			name:     "partial ip",
			input:    "192.168.1",
			expected: "invalid",
		},
		{
			name:     "ip with port (invalid)",
			input:    "192.168.1.1:8080",
			expected: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnonymizeIP(tt.input)
			if result != tt.expected {
				t.Errorf("AnonymizeIP(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAnonymizeIP_SameNetworkProducesSameOutput(t *testing.T) {
	// All IPs in the same /24 should produce the same anonymized output
	ipsInSameNetwork := []string{
		"192.168.1.1",
		"192.168.1.100",
		"192.168.1.255",
		"192.168.1.47",
	}

	expected := "192.168.1.0"
	for _, ip := range ipsInSameNetwork {
		result := AnonymizeIP(ip)
		if result != expected {
			t.Errorf("AnonymizeIP(%q) = %q, want %q (same /24 network)", ip, result, expected)
		}
	}
}

func TestAnonymizeIP_DifferentNetworksProduceDifferentOutput(t *testing.T) {
	// IPs in different /24 networks should produce different anonymized outputs
	result1 := AnonymizeIP("192.168.1.47")
	result2 := AnonymizeIP("192.168.2.47")

	if result1 == result2 {
		t.Errorf("IPs in different networks should produce different outputs: %q vs %q", result1, result2)
	}
}
