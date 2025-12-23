package models

type TenantStatus string

const (
	TenantStatusActive   TenantStatus = "active"
	TenantStatusInactive TenantStatus = "inactive"
)

func (s TenantStatus) IsValid() bool {
	return s == TenantStatusActive || s == TenantStatusInactive
}

func (s TenantStatus) String() string {
	return string(s)
}

type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusInactive ClientStatus = "inactive"
)

func (s ClientStatus) IsValid() bool {
	return s == ClientStatusActive || s == ClientStatusInactive
}

func (s ClientStatus) String() string {
	return string(s)
}
