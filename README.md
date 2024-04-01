<img src="https://github.com/KaiAlan/zkp-protocol/blob/main/assets/zkp%20cover%20-%201.png?raw=true" />

Zero-knowledge proof (ZKP) based protocols allow one party (prover) to convince another (verifier) that a statement is true, without revealing any additional information beyond that fact.

**Here's a simplified breakdown:**

1. *Prover has a secret (like their age).*
2. *Verifier wants to be sure the secret meets a condition (over 21).*
3. *They go through a challenge-response process. Verifier throws challenges, prover responds in a way that proves they meet the condition without revealing the secret itself.*
4. *Verifier is convinced (with high probability) based on the responses.*

---

- Normally, in a ZKP, the prover and verifier engage in a back-and-forth challenge-response to convince the verifier of a statement without revealing any secrets.
- The `Fiat-Shamir heuristic` removes this interaction. It lets the prover compute the challenge themselves using a cryptographic hash function (acting like a random oracle).
- Based on the statement they're trying to prove and the self-generated challenge, the prover creates a proof.
- The verifier can then use the same hash function and the statement to verify the proof.


## Setup

### requirments 

> go 1.22.1


- Step-1: Fork & Clone the repo in your device
- Step-2: Open two seperate terminal
- Step-3: On 1st terminal run ` go run server/server.go `
- Step-4: On 2nd terminal run ` go run client/client.go `

### Test with curl

To test the custom http server implementation with curl

Step-1 : run `  go run zkp-with-custom-http/server/server.go ` on a terminal at root dir
> if the server running succesfully it will start Logging

Step-2: On a seperate terminal run ` curl -vvv -X GET localhost:8080/zkp/initiate `
> The above command will hit the endpoint and recive a keypair of Public and Private key as response and the key pair will be saved to keyPair.json file

Step-3: run ` curl -vvv -X POST -d @keyPair.json localhost:8080/zkp/generate-proof `
> The above command will post the keypair to endpoint and recieve a pair of commitment and response as proof

Step-3: run ` curl -vvv -X POST -d @schnorrProof.json localhost:8080/zkp/proof `
> will recieve a 200 OK HTTP 1.1 response

