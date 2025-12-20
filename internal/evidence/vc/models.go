package vc

import id "credo/pkg/domain"

// VCLifecycle owns verifiable credential issuance and verification rules.
// Anything related to signing, persistence, or registries is orchestrated by
// callers so this type can remain dependency-free.
type VCLifecycle struct{}

func NewVCLifecycle() *VCLifecycle {
	return &VCLifecycle{}
}

type Claims map[string]interface{}

type IssueRequest struct {
	SubjectID id.UserID
	Claims    Claims
}

type IssueResult struct {
	ID         string
	Credential Claims
}

type VerifyRequest struct {
	Credential Claims
}

type VerifyResult struct {
	Valid bool
}

func (l *VCLifecycle) Issue(req IssueRequest) (IssueResult, error) {
	return IssueResult{
		ID:         "todo-credential-id",
		Credential: MinimizeClaims(req.Claims),
	}, nil
}

func (l *VCLifecycle) Verify(req VerifyRequest) (VerifyResult, error) {
	_ = req
	return VerifyResult{Valid: true}, nil
}

// MinimizeClaims removes raw PII while keeping derived assertions. This is a
// placeholder until concrete claim schemas are defined.
func MinimizeClaims(claims Claims) Claims {
	out := Claims{}
	for k, v := range claims {
		// Drop known PII keys.
		if k == "full_name" || k == "national_id" {
			continue
		}
		out[k] = v
	}
	return out
}
