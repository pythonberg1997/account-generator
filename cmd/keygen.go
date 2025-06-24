package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blocto/solana-go-sdk/types"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/blake2b"
)

const (
	suiPrivateKeyPrefix = "suiprivkey"
	ed25519Flag         = 0x00
	addressLength       = 64
)

// KeyGenResult represents the generated keys result
type KeyGenResult struct {
	KeyType     string   `json:"keyType"`
	Count       int      `json:"count"`
	Timestamp   string   `json:"timestamp"`
	PrivateKeys []string `json:"privateKeys"`
	PublicKeys  []string `json:"publicKeys"`
}

func generateEVMKeyPair() (string, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", err
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return privateKeyHex, address, nil
}

func generateSolanaKeyPair() (string, string, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	account, err := types.AccountFromBytes(privateKey)
	if err != nil {
		return "", "", err
	}

	privateKeyBase58 := base58.Encode(privateKey)
	publicKeyBase58 := account.PublicKey.ToBase58()

	return privateKeyBase58, publicKeyBase58, nil
}

func generateSuiKeyPair() (string, string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", "", err
	}

	keyData := append([]byte{ed25519Flag}, seed...)
	converted, err := bech32.ConvertBits(keyData, 8, 5, true)
	if err != nil {
		return "", "", err
	}

	privateKeyStr, err := bech32.Encode(suiPrivateKeyPrefix, converted)
	if err != nil {
		return "", "", err
	}

	priKey := ed25519.NewKeyFromSeed(seed)
	pubKey := priKey.Public().(ed25519.PublicKey)

	tmp := []byte{byte(ed25519Flag)}
	tmp = append(tmp, pubKey...)
	addrBytes := blake2b.Sum256(tmp)
	addr := "0x" + hex.EncodeToString(addrBytes[:])[:addressLength]

	return privateKeyStr, addr, nil
}

// validateSuiPrivateKey validates that a private key can be decoded correctly
func validateSuiPrivateKey(privStr string) error {
	hrp, data, err := bech32.Decode(privStr)
	if err != nil {
		return fmt.Errorf("failed to decode bech32: %w", err)
	}

	if hrp != suiPrivateKeyPrefix {
		return fmt.Errorf("unexpected HRP: got %s, want %s", hrp, suiPrivateKeyPrefix)
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return fmt.Errorf("failed to convert bits: %w", err)
	}

	if len(converted) != 33 { // 1 flag byte + 32 seed bytes
		return fmt.Errorf("invalid key length: got %d, want 33", len(converted))
	}

	seed := converted[1:]
	if len(seed) != 32 {
		return fmt.Errorf("invalid seed length: got %d, want 32", len(seed))
	}

	return nil
}

func main() {
	keyType := flag.String("type", "", "Key type: 'evm', 'solana', or 'sui'")
	count := flag.Int("count", 1, "Number of keypairs to generate")

	flag.Parse()

	if *keyType != "evm" && *keyType != "solana" && *keyType != "sui" {
		fmt.Println("Error: Key type must be 'evm', 'solana', or 'sui'")
		flag.Usage()
		os.Exit(1)
	}

	if *count <= 0 {
		fmt.Println("Error: Count must be greater than 0")
		flag.Usage()
		os.Exit(1)
	}

	privateKeys := make([]string, 0, *count)
	publicKeys := make([]string, 0, *count)

	for i := 0; i < *count; i++ {
		var privateKey, publicKey string
		var err error

		switch *keyType {
		case "evm":
			privateKey, publicKey, err = generateEVMKeyPair()
		case "solana":
			privateKey, publicKey, err = generateSolanaKeyPair()
		case "sui":
			privateKey, publicKey, err = generateSuiKeyPair()
		default:
			fmt.Printf("Error: Invalid key type: %s\n", *keyType)
			flag.Usage()
			os.Exit(1)
		}

		if err != nil {
			fmt.Printf("Error generating keypair %d: %v\n", i+1, err)
			os.Exit(1)
		}

		// Validate Sui private key format
		if *keyType == "sui" {
			if err := validateSuiPrivateKey(privateKey); err != nil {
				fmt.Printf("Error validating sui keypair %d: %v\n", i+1, err)
				os.Exit(1)
			}
		}

		privateKeys = append(privateKeys, privateKey)
		publicKeys = append(publicKeys, publicKey)
	}

	result := KeyGenResult{
		KeyType:     *keyType,
		Count:       *count,
		Timestamp:   time.Now().Format(time.RFC3339),
		PrivateKeys: privateKeys,
		PublicKeys:  publicKeys,
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
		os.Exit(1)
	}

	filename := fmt.Sprintf("%s_keys_%s.json", *keyType, time.Now().Format("20060102_150405"))

	err = os.WriteFile(filename, jsonData, 0o644)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated %d %s keypairs and saved to %s\n", *count, *keyType, filename)
}
