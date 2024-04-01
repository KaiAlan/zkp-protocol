package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	// "fmt"
	"log"
	"math/big"
	"net/http"
)

// Parameters for the Schnorr signature scheme
var (
	prime, _  = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	generator = big.NewInt(2)
)

// KeyPair represents a public-private key pair
type KeyPair struct {
	Public  *big.Int `json:"public"`
	Private *big.Int `json:"private"`
}

// SchnorrProof represents a Schnorr signature proof
type SchnorrProof struct {
	Commitment *big.Int `json:"commitment"`
	Response   *big.Int `json:"response"`
}

// ZKPHandler handles ZKP protocol interactions
type ZKPHandler struct{}

// Initiate handles initiation request
func (h *ZKPHandler) Initiate(w http.ResponseWriter, r *http.Request) {
	// Generate key pair
	privateKey, err := rand.Int(rand.Reader, prime)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	publicKey := new(big.Int).Exp(generator, privateKey, prime)

	keyPair := KeyPair{
		Public:  publicKey,
		Private: privateKey,
	}

	jsonResponse, err := json.Marshal(keyPair)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}

// Proof handles proof request
func (h *ZKPHandler) Proof(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var proof SchnorrProof
	if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// fmt.Println(proof)

	// Verify proof
	// Calculate challenge using Fiat-Shamir heuristic
	hash := sha256.Sum256(proof.Commitment.Bytes())
	challenge := new(big.Int).SetBytes(hash[:])

	// Calculate expected commitment
	expectedCommitment := new(big.Int).Exp(generator, proof.Response, prime)
	expectedCommitment.Mod(expectedCommitment, prime)

	// fmt.Println(proof.Commitment)
	// fmt.Println(expectedCommitment)

	if proof.Commitment.Cmp(expectedCommitment) != 0 {
		fmt.Println("Invalid proof -- Commitment")
		http.Error(w, "Invalid proof -- Commitment", http.StatusUnauthorized)
		return
	}

	// Calculate expected response
	expectedResponse := new(big.Int).Mul(proof.Response, proof.Commitment)
	expectedResponse.Mod(expectedResponse, prime)
	expectedResponse.Add(expectedResponse, challenge)
	expectedResponse.Mod(expectedResponse, prime)

	// fmt.Println(proof.Response)
	// fmt.Println(expectedResponse)

	if proof.Response.Cmp(expectedResponse) != 0 {
		fmt.Println("Invalid proof -- Response")
		http.Error(w, "Invalid proof -- Response", http.StatusUnauthorized)
		return
	}

	// Proof is valid
	w.WriteHeader(http.StatusOK)
}

func main() {
	zkpHandler := &ZKPHandler{}

	http.HandleFunc("/zkp/initiate", zkpHandler.Initiate)
	http.HandleFunc("/zkp/proof", zkpHandler.Proof)

	log.Println("Starting ZKP server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
