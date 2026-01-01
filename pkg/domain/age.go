package domain

import "time"

// IsOver18 returns true if the person with the given birth date is 18 years old or older
// at the specified reference time. Uses calendar arithmetic (AddDate) for accurate
// birthday-boundary handling.
//
// Example:
//
//	birthDate := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
//	now := time.Date(2018, 1, 15, 0, 0, 0, 0, time.UTC) // Exactly 18th birthday
//	IsOver18(birthDate, now) // returns true
func IsOver18(birthDate, now time.Time) bool {
	adultAt := birthDate.UTC().AddDate(18, 0, 0)
	return !now.UTC().Before(adultAt)
}
