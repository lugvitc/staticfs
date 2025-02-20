package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"encoding/base64"
	"github.com/celestix/staticfs/middleware"
	//	"github.com/celestix/staticfs/utils"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func loadSecretKey() ([]byte, error) {
	secretKey := os.Getenv("JWT_SECRET")
	if secretKey == "" {
		return nil, fmt.Errorf("PUBLIC_KEY environment variable not set")
	}
	return base64.StdEncoding.DecodeString(secretKey)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dataDir := os.Getenv("DATA_DIR")
	r := gin.Default()
	secretKey, err := loadSecretKey()
	if err != nil {
		log.Fatalf("Error loading public key: %v", err)
	}
	r.Use(middleware.AuthMiddleware(secretKey))
	r.GET("/*filepath", func(c *gin.Context) {
		teamID := c.MustGet("teamId").(string)
		containerID := c.MustGet("containerId").(string)
		requestedFile := c.Param("filepath")

		// Clean the file path to prevent directory traversal attacks.
		fullPath := filepath.Join(dataDir, teamID, containerID, filepath.Clean(requestedFile))
		fmt.Println(fullPath)
		c.File(fullPath)
	})
	//	token, err := utils.CreateJWT("randomteam123", "randomcontainer123", secretKey)
	//	if err != nil {
	//		log.Fatalf("Failed to generate JWT: %v", err)
	//	}
	//	fmt.Println("Generated JWT:", token)
	r.Run()
}
