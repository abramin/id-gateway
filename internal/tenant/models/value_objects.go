package models

// TenantStatus represents the lifecycle state of a tenant.
type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
)

// IsValid checks if the tenant status is one of the supported enum values.
func (s TenantStatus) IsValid() bool {
	return s == TenantStatusActive || s == TenantStatusInactive
}

// String returns the string representation of the tenant status.
func (s TenantStatus) String() string {
	return string(s)
}

// ClientStatus represents the lifecycle state of a client.
type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusInactive ClientStatus = "inactive"
)

// IsValid checks if the client status is one of the supported enum values.
func (s ClientStatus) IsValid() bool {
	return s == ClientStatusActive || s == ClientStatusInactive
}

// String returns the string representation of the client status.
func (s ClientStatus) String() string {
	return string(s)
}
