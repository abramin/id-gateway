package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	defaultPort      = "8082"
	defaultAPIKey    = "sanctions-registry-secret-key"
	defaultLatencyMs = "50"
)

type SanctionsRequest struct {
	NationalID string `json:"national_id"`
}

type SanctionsResponse struct {
	NationalID string `json:"national_id"`
	Listed     bool   `json:"listed"`
	Source     string `json:"source"`
	ListType   string `json:"list_type,omitempty"`   // "sanctions", "pep", "watchlist"
	Reason     string `json:"reason,omitempty"`      // Why they're listed
	ListedDate string `json:"listed_date,omitempty"` // When added to list
	CheckedAt  string `json:"checked_at"`
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

// listedSanctions contains predefined test national IDs that should be marked as listed.
// These "magic" IDs allow e2e tests to control the mock's behavior.
var listedSanctions = map[string]bool{
	"SANCTIONED123":  true, // Used for decision rule chain tests
	"SANCTIONED999":  true, // Used for sanctions screening tests
	"SANCTIONED99":   true, // Used for registry sanctions-listed tests
	"SANCTIONED_PEP": true, // Politically exposed person
	"WATCHLIST001":   true, // Watchlist entry
}

// notListedSanctions contains national IDs that should always be NOT listed (override hash behavior).
var notListedSanctions = map[string]bool{
	"ADULT123456":   true, // Adult user - should not be sanctioned
	"NOCRED123456":  true, // No credential user - should not be sanctioned
	"CLEAN123456":   true, // Clean user for sanctions screening
	"MINOR123456":   true, // Minor user - not sanctioned
	"INVALID12345":  true, // Invalid citizen - not sanctioned
	"INVALID123456": true, // Invalid citizen (alternate) - not sanctioned
	"EXACT18":       true, // Exactly 18 years old - not sanctioned
	"JUSTTURNED18":  true, // Just turned 18 - not sanctioned
	"MINOR17":       true, // Minor - not sanctioned
}

func main() {
	port := getEnv("PORT", defaultPort)

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/api/v1/sanctions/check", handleSanctionsCheck)
	http.HandleFunc("/lookup", handleSanctionsCheck) // Simplified path for adapter

	log.Printf("⚖️  Mock Sanctions Registry API starting on port %s", port)
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
		"service": "sanctions-registry",
		"version": "1.0.0",
	})
}

func handleSanctionsCheck(w http.ResponseWriter, r *http.Request) {
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
	var req SanctionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate national ID
	if req.NationalID == "" {
		sendError(w, "national_id is required", http.StatusBadRequest)
		return
	}

	// Generate deterministic sanctions data based on national ID
	sanctions := generateSanctions(req.NationalID)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(sanctions)

	if sanctions.Listed {
		log.Printf("🚨 Sanctions check: %s -> LISTED (%s)", req.NationalID, sanctions.ListType)
	} else {
		log.Printf("✅ Sanctions check: %s -> NOT LISTED", req.NationalID)
	}
}

func generateSanctions(nationalID string) SanctionsResponse {
	// Check for predefined test IDs first
	if listedSanctions[nationalID] {
		log.Printf("🧪 Using predefined LISTED sanctions data for: %s", nationalID)
		return SanctionsResponse{
			NationalID: nationalID,
			Listed:     true,
			Source:     "Mock International Sanctions Database",
			ListType:   "sanctions",
			Reason:     "OFAC SDN List - Test Entry",
			ListedDate: time.Now().AddDate(-2, 0, 0).Format("2006-01-02"),
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}
	if notListedSanctions[nationalID] {
		log.Printf("🧪 Using predefined NOT LISTED sanctions data for: %s", nationalID)
		return SanctionsResponse{
			NationalID: nationalID,
			Listed:     false,
			Source:     "Mock International Sanctions Database",
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Use hash to generate deterministic but pseudo-random data
	hash := sha256.Sum256([]byte(nationalID))
	hashStr := hex.EncodeToString(hash[:])
	hashInt := int(hash[0])

	// Determine if listed (10% chance of being listed)
	// Use last two hex digits for deterministic check
	lastTwoHex := hashStr[len(hashStr)-2:]
	listed := lastTwoHex == "00" || lastTwoHex == "ff" || lastTwoHex == "11" || lastTwoHex == "22" ||
		lastTwoHex == "33" || lastTwoHex == "44" || lastTwoHex == "55" || lastTwoHex == "66" ||
		lastTwoHex == "77" || lastTwoHex == "88"

	response := SanctionsResponse{
		NationalID: nationalID,
		Listed:     listed,
		Source:     "Mock International Sanctions Database",
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	if listed {
		// Determine list type
		listTypes := []string{"sanctions", "pep", "watchlist"}
		response.ListType = listTypes[hashInt%len(listTypes)]

		// Determine reason
		reasons := map[string][]string{
			"sanctions": {
				"UN Security Council Resolution 1234",
				"EU Sanctions List - Financial Crimes",
				"OFAC SDN List - Money Laundering",
				"International Arms Embargo",
			},
			"pep": {
				"Politically Exposed Person - Government Official",
				"Politically Exposed Person - Family Member",
				"Politically Exposed Person - Close Associate",
			},
			"watchlist": {
				"Enhanced Due Diligence Required",
				"Adverse Media - Financial Crimes",
				"Law Enforcement Interest",
			},
		}

		reasonList := reasons[response.ListType]
		response.Reason = reasonList[hashInt%len(reasonList)]

		// Determine listed date (1-5 years ago)
		yearsAgo := 1 + (hashInt % 5)
		listedDate := time.Now().AddDate(-yearsAgo, -(hashInt % 12), -(hashInt % 28))
		response.ListedDate = listedDate.Format("2006-01-02")
	}

	return response
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
