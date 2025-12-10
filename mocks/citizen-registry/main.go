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

	// Generate deterministic citizen data based on national ID
	citizen := generateCitizen(req.NationalID)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(citizen)

	log.Printf("✅ Citizen lookup successful: %s -> %s", req.NationalID, citizen.FullName)
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
