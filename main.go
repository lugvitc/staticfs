package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lugvitc/staticfs/middleware"
	"github.com/lugvitc/staticfs/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalln("Error loading .env file")
	}
	dataDir := os.Getenv("DATA_DIR")
	r := gin.Default()
	secretKey := os.Getenv("JWT_SECRET")
	if secretKey == "" {
		log.Fatalln("JWT_SECRET environment variable not set")
	}
	r.Use(middleware.AuthMiddleware([]byte(secretKey)))
	r.GET("/:token/*filepath", func(c *gin.Context) {
		teamID := c.MustGet("teamId").(string)
		containerID := c.MustGet("containerId").(string)
		requestedFile := c.Param("filepath")
		// Clean the file path to prevent directory traversal attacks.
		fullPath := filepath.Join(dataDir, teamID, containerID, filepath.Clean(requestedFile))
		fmt.Println("Requested file:", requestedFile)
		c.File(fullPath)
	})
	fmt.Println(utils.CreateJWT("bruh", "wtf", []byte(secretKey)))
	r.Run()
}
