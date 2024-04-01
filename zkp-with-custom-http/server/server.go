package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

// Parameters for the Schnorr signature scheme
var (
	prime, _   = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10)
	generator  = big.NewInt(2)
	Public_Key *big.Int
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

	fmt.Println("Logging...")

	//binding to port
	listner, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		fmt.Println("Failed to bind to port 8080")
		os.Exit(1)
	}
	defer listner.Close()

	for {

		conn, err := listner.Accept()

		if err != nil {
			fmt.Println("Error accepting connection: ", err.Error())
			os.Exit(1)
		}

		fmt.Println("Client connected: ", conn.RemoteAddr())

		go handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {

	defer conn.Close()

	//reading incomig requests
	readBuffer := make([]byte, 2048)
	bytesReceived, err := conn.Read(readBuffer)

	if err != nil {
		fmt.Printf("Error reading request: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Read %d bytes from client\n", bytesReceived)

	request := string(readBuffer[:bytesReceived])

	//Paresing Request and Responsing with proper response

	method, path, _ := ParseRequest(request)

	httpResponse := "HTTP/1.1 200 OK\r\n\r\n"
	defaultResponse := "HTTP/1.1 404 Not Found\r\n\r\n"

	if method == "GET" {

		if path == "/" {
			_, err := conn.Write([]byte(httpResponse))

			if err != nil {
				fmt.Println("Error sending response: ", err.Error())
				os.Exit(1)
			}
		} else if path == "/zkp/initiate" {

			// Generate key pair
			privateKey, err := rand.Int(rand.Reader, prime)
			if err != nil {
				conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
				return
			}
			publicKey := new(big.Int).Mul(privateKey, generator)
			Public_Key = publicKey

			keyPair := KeyPair{
				Public:  publicKey,
				Private: privateKey,
			}

			jsonResponse, err := json.Marshal(keyPair)

			if err != nil {
				conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
				return
			}

			// write keyPair to a file for further testing with curl

			errWritingToFile := os.WriteFile("keyPair.json", []byte(jsonResponse), 0666)

			if errWritingToFile == nil {

				// Send keyPair back as response
				response := setResponse("200", "OK", "text/plain", strconv.Itoa(len(jsonResponse)), string(jsonResponse))
				sendResponse(response, conn)
			} else {
				fmt.Println("Server Error: ", errWritingToFile.Error())
				return
			}

		} else {
			_, err := conn.Write([]byte(defaultResponse))

			if err != nil {
				fmt.Println("Error sending response: ", err.Error())
				os.Exit(1)
			}
		}
	} else if method == "POST" {

		if path == "/zkp/proof" {

			requestBody := strings.Split(request, "\r\n\r\n")[1]

			var proof SchnorrProof

			proof.Commitment, proof.Response = ParseRequestForProof(requestBody)

			// Verify proof
			// Calculate challenge using Fiat-Shamir heuristic
			hash := sha256.Sum256(proof.Commitment.Bytes())
			challenge := new(big.Int).SetBytes(hash[:])

			// Calculate expected commitment
			expectedCommitment := new(big.Int).Mul(challenge, Public_Key)
			expectedCommitment.Add(expectedCommitment, proof.Commitment)

			// Calculate expected response
			expectedResponse := new(big.Int).Mul(proof.Response, generator)

			if expectedCommitment.Cmp(expectedResponse) != 0 {
				conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
				return
			}

			// Proof is valid
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		} else if path == "/zkp/generate-proof" {

			// FOR TESTING THROUGH CURL

			requestBody := strings.Split(request, "\r\n\r\n")[1]

			// fmt.Println(request)

			var keyPair KeyPair

			keyPair.Public, keyPair.Private = ParseRequestForProof(requestBody)

			Public_Key = keyPair.Public

			// Generate proof using Fiat-Shamir heuristic
			proof, err := generateProof(&keyPair)
			if err != nil {
				log.Fatalf("Failed to generate proof: %v", err)
			}

			jsonProof, err := json.Marshal(proof)

			if err != nil {
				conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
				return
			}
			// Write proof to a schnorrProof.json file @root dir
			errWritingToFile := os.WriteFile("schnorrProof.json", jsonProof, 0666)

			if errWritingToFile != nil {
				fmt.Println("Server Error: ", errWritingToFile.Error())
				return
			}

			// Proof Successfully created and saved
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		} else {
			_, err := conn.Write([]byte(defaultResponse))

			if err != nil {
				fmt.Println("Error sending response: ", err.Error())
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("Not a valid request")
	}

}

func ParseRequest(request string) (string, string, string) {

	requestFirstLine := strings.Split(request, "\r\n")[0]
	requestParams := strings.Split(requestFirstLine, " ")

	method := requestParams[0]
	path := requestParams[1]
	version := requestParams[2]

	return method, path, version
}

func ParseRequestForProof(requestBody string) (*big.Int, *big.Int) {

	// Cleaning of response
	value_1, value_2, _ := strings.Cut(requestBody, ",")
	_, value_1, _ = strings.Cut(value_1, ":")
	_, value_2, _ = strings.Cut(value_2, ":")
	value_2 = strings.TrimRight(value_2, "}")

	// converting value string to big int

	i := new(big.Int)
	i, i_ok := i.SetString(value_1, 10)

	if !i_ok {
		fmt.Println("Not able to convert i")
	}

	j := new(big.Int)
	j, j_ok := j.SetString(value_2, 10)

	if !j_ok {
		fmt.Println("Not able to convert i")
	}

	return i, j
}

func setResponse(statusCode string, statusMessage string, contentType string, contentLength string, responseBody string) string {
	response := "HTTP/1.1 " + statusCode + " " + statusMessage + "\r\n"
	response += "Content-type: " + contentType + "\r\n"
	response += "Content-length: " + contentLength + "\r\n\r\n"
	response += responseBody

	return response
}

func sendResponse(response string, conn net.Conn) {
	bytesSent, err := conn.Write([]byte(response))

	if err != nil {
		fmt.Println("Error sending response: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Sent %d bytes to client (expected: %d)\n", bytesSent, len(response))
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
