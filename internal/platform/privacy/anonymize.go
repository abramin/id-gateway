// Package privacy provides utilities for handling personally identifiable information (PII)
// in a GDPR-compliant manner.
package privacy

import (
	"fmt"
	"net"
)

// AnonymizeIP truncates an IP address to remove the host-identifying portion,
// providing GDPR-compliant anonymization.
//
// For IPv4 addresses, the last octet is zeroed (e.g., "192.168.1.47" -> "192.168.1.0"),
// effectively masking to a /24 network.
//
// For IPv6 addresses, the last 80 bits are zeroed, showing only the /48 prefix
// (e.g., "2001:db8:85a3::8a2e:370:7334" -> "2001:db8:85a3::").
//
// This approach satisfies GDPR anonymization requirements as the resulting value
// cannot identify a specific individual (up to 256 hosts share the same anonymized IPv4).
//
// Returns "invalid" for unparseable IP addresses, and "unknown" for empty strings.
func AnonymizeIP(ip string) string {
	if ip == "" || ip == "unknown" {
		return "unknown"
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "invalid"
	}

	// Check for IPv4 (including IPv4-mapped IPv6)
	if v4 := parsed.To4(); v4 != nil {
		// Zero the last octet for /24 anonymization
		return fmt.Sprintf("%d.%d.%d.0", v4[0], v4[1], v4[2])
	}

	// IPv6: Zero the last 80 bits, keeping only the /48 prefix
	// IPv6 is 16 bytes, /48 prefix = first 6 bytes
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x::",
		parsed[0], parsed[1],
		parsed[2], parsed[3],
		parsed[4], parsed[5])
}
