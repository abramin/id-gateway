package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	defaultPort      = "8081"
	defaultAPIKey    = "citizen-registry-secret-key"
	defaultLatencyMs = "100"
)

type CitizenRequest struct {
	NationalID string `json:"national_id"`
}

type CitizenResponse struct {
	NationalID  string `json:"national_id"`
	FullName    string `json:"full_name"`
	DateOfBirth string `json:"date_of_birth"`
	Address     string `json:"address"`
	Valid       bool   `json:"valid"`
	CheckedAt   string `json:"checked_at"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

var (
	apiKey    = getEnv("API_KEY", defaultAPIKey)
	latencyMs = getEnvInt("LATENCY_MS", defaultLatencyMs)
)

func main() {
	port := getEnv("PORT", defaultPort)

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/api/v1/citizen/lookup", handleCitizenLookup)
	http.HandleFunc("/lookup", handleCitizenLookup) // Simplified path for adapter

	log.Printf("🏛️  Mock Citizen Registry API starting on port %s", port)
	log.Printf("📝 API Key: %s", apiKey)
	log.Printf("⏱️  Simulated latency: %dms", latencyMs)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "citizen-registry",
		"version": "1.0.0",
	})
}

// testCitizens contains predefined test data for specific national IDs.
// These "magic" IDs allow e2e tests to control the mock's behavior.
var testCitizens = map[string]func() *CitizenResponse{
	// Adults - valid citizens over 18
	"ADULT123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "ADULT123456",
			FullName:    "John Adult Smith",
			DateOfBirth: "1990-01-01",
			Address:     "123 Main St, Springfield, CA 90210",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"FMTCHECK123": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "FMTCHECK123",
			FullName:    "Format Check User",
			DateOfBirth: "1985-06-15",
			Address:     "456 Oak Ave, Riverside, TX 75001",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"REGULATED123": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "REGULATED123",
			FullName:    "Regulated Mode User",
			DateOfBirth: "1980-03-15",
			Address:     "789 Pine Dr, Fairview, NY 10001",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"FULLDATA123": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "FULLDATA123",
			FullName:    "Full Data User",
			DateOfBirth: "1975-12-25",
			Address:     "321 Elm St, Clinton, FL 33101",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"AUDIT123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "AUDIT123456",
			FullName:    "Audit Trail User",
			DateOfBirth: "1988-07-20",
			Address:     "654 Cedar Ln, Georgetown, IL 60601",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"MULTI123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "MULTI123456",
			FullName:    "Multi Request User",
			DateOfBirth: "1992-04-10",
			Address:     "987 Birch Way, Franklin, PA 19101",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	// Underage users - for age verification tests
	"MINOR17": func() *CitizenResponse {
		// Calculate birth date to be exactly 17 years old (plus a bit to ensure under 18)
		birthDate := time.Now().AddDate(-17, 0, 1).Format("2006-01-02")
		return &CitizenResponse{
			NationalID:  "MINOR17",
			FullName:    "Minor Seventeen User",
			DateOfBirth: birthDate,
			Address:     "111 Youth St, Fairview, CA 90001",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"JUSTTURNED18": func() *CitizenResponse {
		// Calculate birth date to be exactly 18 years old today
		birthDate := time.Now().AddDate(-18, 0, 0).Format("2006-01-02")
		return &CitizenResponse{
			NationalID:  "JUSTTURNED18",
			FullName:    "Just Turned Eighteen",
			DateOfBirth: birthDate,
			Address:     "222 Birthday Ln, Madison, TX 75002",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	// Invalid citizen record
	"INVALID12345": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "INVALID12345",
			FullName:    "Invalid Record User",
			DateOfBirth: "1980-01-01",
			Address:     "333 Invalid Ave, Salem, OH 44001",
			Valid:       false, // Invalid citizen
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	// Decision test citizens
	"NOCRED123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "NOCRED123456",
			FullName:    "No Credential User",
			DateOfBirth: "1990-01-15",
			Address:     "444 Nocred St, Springfield, CA 90211",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"SANCTIONED123": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "SANCTIONED123",
			FullName:    "Sanctioned User",
			DateOfBirth: "1990-01-15",
			Address:     "555 Sanctions Ave, Restricted, NY 10002",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"INVALID123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "INVALID123456",
			FullName:    "Invalid Citizen User",
			DateOfBirth: "1990-01-15",
			Address:     "666 Invalid Rd, Nowhere, TX 75003",
			Valid:       false, // Invalid citizen
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"MINOR123456": func() *CitizenResponse {
		// 16 years old
		birthDate := time.Now().AddDate(-16, 0, 0).Format("2006-01-02")
		return &CitizenResponse{
			NationalID:  "MINOR123456",
			FullName:    "Minor Sixteen User",
			DateOfBirth: birthDate,
			Address:     "777 Youth Ln, Kidsville, FL 33102",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"EXACT18": func() *CitizenResponse {
		// Exactly 18 years old today
		birthDate := time.Now().AddDate(-18, 0, 0).Format("2006-01-02")
		return &CitizenResponse{
			NationalID:  "EXACT18",
			FullName:    "Exactly Eighteen User",
			DateOfBirth: birthDate,
			Address:     "888 Birthday Blvd, Adulthood, GA 30301",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"CLEAN123456": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "CLEAN123456",
			FullName:    "Clean Record User",
			DateOfBirth: "1990-01-15",
			Address:     "999 Clean St, Clearville, WA 98001",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
	"SANCTIONED999": func() *CitizenResponse {
		return &CitizenResponse{
			NationalID:  "SANCTIONED999",
			FullName:    "Sanctions Test User",
			DateOfBirth: "1985-05-20",
			Address:     "101 Restricted Dr, Blocked, AZ 85001",
			Valid:       true,
			CheckedAt:   time.Now().UTC().Format(time.RFC3339),
		}
	},
}

// notFoundCitizens contains national IDs that should return 404
var notFoundCitizens = map[string]bool{
	"UNKNOWN999":   true,
	"NOCONSENT123": true, // Used for consent tests - no citizen data needed
	"REVOKED123":   true, // Used for consent revocation tests
}

func handleCitizenLookup(w http.ResponseWriter, r *http.Request) {
	// Simulate latency
	time.Sleep(time.Duration(latencyMs) * time.Millisecond)

	// Log request
	log.Printf("📥 Incoming request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Only accept POST
	if r.Method != http.MethodPost {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check API key
	authHeader := r.Header.Get("X-API-Key")
	if authHeader == "" {
		sendError(w, "Missing X-API-Key header", http.StatusUnauthorized)
		return
	}
	if authHeader != apiKey {
		sendError(w, "Invalid API key", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req CitizenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate national ID
	if req.NationalID == "" {
		sendError(w, "national_id is required", http.StatusBadRequest)
		return
	}

	// Check for test "not found" IDs
	if notFoundCitizens[req.NationalID] {
		sendError(w, "Citizen not found", http.StatusNotFound)
		log.Printf("🔍 Citizen not found (test ID): %s", req.NationalID)
		return
	}

	// Check for predefined test citizens
	var citizen CitizenResponse
	if testFn, ok := testCitizens[req.NationalID]; ok {
		citizen = *testFn()
		log.Printf("🧪 Using test citizen data for: %s", req.NationalID)
	} else {
		// Generate deterministic citizen data based on national ID
		citizen = generateCitizen(req.NationalID)
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(citizen)

	log.Printf("✅ Citizen lookup successful: %s -> %s (valid=%v)", req.NationalID, citizen.FullName, citizen.Valid)
}

func generateCitizen(nationalID string) CitizenResponse {
	// Use hash to generate deterministic but pseudo-random data
	hash := sha256.Sum256([]byte(nationalID))
	hashStr := hex.EncodeToString(hash[:])
	hashInt := int(hash[0])

	// Generate deterministic name
	firstNames := []string{"Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry", "Isabel", "Jack"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"}
	middleNames := []string{"Marie", "James", "Lynn", "Michael", "Ann", "Robert", "Elizabeth", "William", "Rose", "Joseph"}

	firstName := firstNames[hashInt%len(firstNames)]
	middleName := middleNames[(hashInt*2)%len(middleNames)]
	lastName := lastNames[(hashInt*3)%len(lastNames)]
	fullName := fmt.Sprintf("%s %s %s", firstName, middleName, lastName)

	// Generate deterministic date of birth (age between 18-80)
	age := 18 + (hashInt % 62)
	birthYear := time.Now().Year() - age
	birthMonth := 1 + (hashInt % 12)
	birthDay := 1 + (hashInt % 28)
	dateOfBirth := fmt.Sprintf("%04d-%02d-%02d", birthYear, birthMonth, birthDay)

	// Generate deterministic address
	streetNumber := 100 + (hashInt % 900)
	streets := []string{"Main St", "Oak Ave", "Maple Dr", "Pine Rd", "Elm St", "Cedar Ln", "Birch Way", "Willow Ct", "Cherry Blvd", "Ash Pl"}
	cities := []string{"Springfield", "Riverside", "Fairview", "Clinton", "Georgetown", "Franklin", "Madison", "Salem", "Arlington", "Lexington"}
	states := []string{"CA", "TX", "FL", "NY", "IL", "PA", "OH", "GA", "NC", "MI"}
	zipCode := 10000 + (hashInt * 123 % 90000)

	street := streets[hashInt%len(streets)]
	city := cities[(hashInt*2)%len(cities)]
	state := states[(hashInt*3)%len(states)]
	address := fmt.Sprintf("%d %s, %s, %s %05d", streetNumber, street, city, state, zipCode)

	// Determine validity (95% valid, use last 4 chars of hash)
	valid := hashStr[len(hashStr)-4:] != "0000"

	return CitizenResponse{
		NationalID:  nationalID,
		FullName:    fullName,
		DateOfBirth: dateOfBirth,
		Address:     address,
		Valid:       valid,
		CheckedAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

func sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	})
	log.Printf("❌ Error response: %d - %s", code, message)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key, defaultValue string) int {
	value := getEnv(key, defaultValue)
	intValue, err := strconv.Atoi(value)
	if err != nil {
		log.Printf("⚠️  Invalid integer value for %s, using default: %s", key, defaultValue)
		intValue, _ = strconv.Atoi(defaultValue)
	}
	return intValue
}
