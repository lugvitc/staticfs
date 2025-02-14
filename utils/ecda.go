package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// generateKeyPair creates a new ECDSA private/public key pair using the P-256 curve.
func GenerateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return privKey, &privKey.PublicKey, nil
}

// encodePrivateKeyToPEM encodes the ECDSA private key into PEM format.
func EncodePrivateKeyToPEM(privKey *ecdsa.PrivateKey) ([]byte, error) {
	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})
	return privPEM, nil
}

// encodePublicKeyToPEM encodes the ECDSA public key into PEM format.
// This format is compatible with your loadPublicKey function.
func EncodePublicKeyToPEM(pubKey *ecdsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return pubPEM, nil
}

// func main() {
// 	// Generate the key pair.
// 	privKey, pubKey, err := generateKeyPair()
// 	if err != nil {
// 		log.Fatalf("Error generating key pair: %v", err)
// 	}
//
// 	// Encode the private key to PEM format.
// 	privPEM, err := encodePrivateKeyToPEM(privKey)
// 	if err != nil {
// 		log.Fatalf("Error encoding private key: %v", err)
// 	}
//
// 	// Encode the public key to PEM format.
// 	pubPEM, err := encodePublicKeyToPEM(pubKey)
// 	if err != nil {
// 		log.Fatalf("Error encoding public key: %v", err)
// 	}
//
// 	fmt.Println("Generated ECDSA Key Pair:")
// 	fmt.Println("Private Key (PEM):")
// 	fmt.Println(string(privPEM))
// 	fmt.Println("Public Key (PEM):")
// 	fmt.Println(string(pubPEM))
// }
