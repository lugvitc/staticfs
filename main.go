package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/celestix/staticfs/middleware"
	"github.com/celestix/staticfs/utils"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func loadPublicKey() (*ecdsa.PublicKey, error) {
	pubKeyPEM := os.Getenv("PUBLIC_KEY")
	if pubKeyPEM == "" {
		return nil, fmt.Errorf("PUBLIC_KEY environment variable not set")
	}
	return utils.DecodePublicKeyFromPEM([]byte(pubKeyPEM))
}

// func loadPriKey() (*ecdsa.PrivateKey, error) {
// 	priKeyPEM := os.Getenv("PRIVATE_KEY")
// 	if priKeyPEM == "" {
// 		return nil, fmt.Errorf("PRIVATE_KEY environment variable not set")
// 	}
// 	return utils.DecodePrivateKeyFromPEM([]byte(priKeyPEM))
// }

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dataDir := os.Getenv("DATA_DIR")
	r := gin.Default()
	pubKey, err := loadPublicKey()
	if err != nil {
		log.Fatalf("Error loading public key: %v", err)
	}
	//	priKey, err := loadPriKey()
	//	if err != nil {
	//		log.Fatalf("Error loading private key: %v", err)
	//	}
	r.Use(middleware.AuthMiddleware(pubKey))
	r.GET("/:team_id/:container_id/*filepath", func(c *gin.Context) {
		teamID := c.Param("team_id")
		containerID := c.Param("container_id")
		requestedFile := c.Param("filepath")

		// Clean the file path to prevent directory traversal attacks.
		fullPath := filepath.Join(dataDir, teamID, containerID, filepath.Clean(requestedFile))
		fmt.Println(fullPath)
		c.File(fullPath)
	})
	//	token, err := utils.CreateJWT("randomteam123", "randomcontainer123", priKey)
	//	if err != nil {
	//		log.Fatalf("Failed to generate JWT: %v", err)
	//	}
	//	fmt.Println("Generated JWT:", token)
	r.Run()
}
