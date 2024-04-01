package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
)

// Parameters for the Schnorr signature scheme
var (
	prime, _   = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	generator  = big.NewInt(2)
	serverAddr = "http://localhost:8080"
	// Private_Key *big.Int
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

func main() {
	// Step 1: Request key pair from server
	keyPair, err := requestKeyPair()
	if err != nil {
		log.Fatalf("Failed to request key pair: %v", err)
	}
	// Private_Key = keyPair.Private

	// fmt.Println(keyPair)

	// Step 2: Generate proof using Fiat-Shamir heuristic
	proof, err := generateProof(keyPair)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}

	// fmt.Println(*proof)

	// Step 3: Send proof to server for verification
	err = sendProof(proof)
	if err != nil {
		log.Fatalf("Failed to send proof: %v", err)
	}

	fmt.Println("Proof sent successfully!")
}

func requestKeyPair() (*KeyPair, error) {
	resp, err := http.Get(serverAddr + "/zkp/initiate")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var keyPair KeyPair
	err = json.NewDecoder(resp.Body).Decode(&keyPair)
	if err != nil {
		return nil, err
	}

	return &keyPair, nil
}

func generateProof(keyPair *KeyPair) (*SchnorrProof, error) {
	// Generate random nonce
	nonce, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}

	// Compute commitment
	commitment := new(big.Int).Mul(generator, nonce)

	// Calculate challenge using Fiat-Shamir heuristic
	hash := sha256.Sum256(commitment.Bytes())
	challenge := new(big.Int).SetBytes(hash[:])

	// Calculate response
	response := new(big.Int).Mul(challenge, keyPair.Private)
	response.Add(response, nonce)

	return &SchnorrProof{
		Commitment: commitment,
		Response:   response,
	}, nil
}

func sendProof(proof *SchnorrProof) error {
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		return err
	}

	// fmt.Println(proofJSON)

	resp, err := http.Post(serverAddr+"/zkp/proof", "application/json", bytes.NewBuffer(proofJSON))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// fmt.Println(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status code: %d", resp.StatusCode)
	}

	return nil
}
