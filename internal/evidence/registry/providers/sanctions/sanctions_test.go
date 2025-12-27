package sanctions

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/providers"
)

type SanctionsParserSuite struct {
	suite.Suite
}

func TestSanctionsParserSuite(t *testing.T) {
	suite.Run(t, new(SanctionsParserSuite))
}

// TestParseSanctionsResponse verifies parser contract.
// Invariant: Valid JSON with 200 status must produce Evidence with correct fields.
func (s *SanctionsParserSuite) TestParseSanctionsResponse() {
	s.Run("parses valid response with listed subject", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": true,
			"source": "OFAC-SDN",
			"checked_at": "2025-12-11T10:00:00Z"
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err)
		s.Require().NotNil(evidence)

		s.Equal(providers.ProviderTypeSanctions, evidence.ProviderType)
		s.Equal(1.0, evidence.Confidence, "sanctions provider is authoritative")
		s.Equal("123456789012", evidence.Data["national_id"])
		s.Equal(true, evidence.Data["listed"])
		s.Equal("OFAC-SDN", evidence.Data["source"])
		s.False(evidence.CheckedAt.IsZero(), "valid timestamp should be parsed")
	})

	s.Run("parses unlisted subject", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": false,
			"source": "OFAC-SDN",
			"checked_at": "2025-12-11T10:00:00Z"
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err)
		s.Require().NotNil(evidence)

		s.Equal(false, evidence.Data["listed"])
	})
}

// TestParseSanctionsResponse_Non200Status verifies error handling.
// Invariant: Non-200 status must fail, not silently succeed with bad data.
func (s *SanctionsParserSuite) TestParseSanctionsResponse_Non200Status() {
	// Single parameter varies (status code) - table test is appropriate
	codes := []int{400, 401, 404, 500, 503}
	for _, code := range codes {
		code := code // capture for closure
		s.Run(fmt.Sprintf("rejects status %d", code), func() {
			evidence, err := parseSanctionsResponse(code, []byte(`{}`))
			s.Error(err)
			s.Nil(evidence)
			s.Contains(err.Error(), "unexpected status code")
		})
	}
}

// TestParseSanctionsResponse_MalformedJSON verifies error handling.
// Invariant: Invalid JSON must fail, not panic or return corrupt data.
func (s *SanctionsParserSuite) TestParseSanctionsResponse_MalformedJSON() {
	s.Run("rejects invalid JSON syntax", func() {
		evidence, err := parseSanctionsResponse(200, []byte(`{invalid json`))
		s.Error(err)
		s.Nil(evidence)
	})

	s.Run("rejects truncated JSON", func() {
		evidence, err := parseSanctionsResponse(200, []byte(`{"national_id": "123`))
		s.Error(err)
		s.Nil(evidence)
	})

	s.Run("rejects empty body", func() {
		evidence, err := parseSanctionsResponse(200, []byte(``))
		s.Error(err)
		s.Nil(evidence)
	})

	s.Run("rejects array instead of object", func() {
		evidence, err := parseSanctionsResponse(200, []byte(`[]`))
		s.Error(err)
		s.Nil(evidence)
	})
}

// TestParseSanctionsResponse_InvalidTimestamp verifies domain purity.
// Invariant: Parser doesn't call time.Now(); invalid timestamp leaves zero for adapter to fill.
func (s *SanctionsParserSuite) TestParseSanctionsResponse_InvalidTimestamp() {
	s.Run("leaves CheckedAt zero for invalid date format", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": false,
			"source": "OFAC-SDN",
			"checked_at": "invalid-date"
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err, "parser should not fail on invalid timestamp")
		s.Require().NotNil(evidence)
		s.True(evidence.CheckedAt.IsZero(), "parser leaves zero for adapter to fill")
	})

	s.Run("leaves CheckedAt zero for empty string", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": false,
			"source": "OFAC-SDN",
			"checked_at": ""
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err)
		s.True(evidence.CheckedAt.IsZero())
	})

	s.Run("leaves CheckedAt zero for wrong format", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": false,
			"source": "OFAC-SDN",
			"checked_at": "2025-12-11"
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err)
		s.True(evidence.CheckedAt.IsZero(), "non-RFC3339 format leaves zero")
	})

	s.Run("leaves CheckedAt zero for unix timestamp", func() {
		body := []byte(`{
			"national_id": "123456789012",
			"listed": false,
			"source": "OFAC-SDN",
			"checked_at": "1733914800"
		}`)

		evidence, err := parseSanctionsResponse(200, body)
		s.Require().NoError(err)
		s.True(evidence.CheckedAt.IsZero())
	})
}
