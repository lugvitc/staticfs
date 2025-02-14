package middleware

import (
	"crypto/ecdsa"
	"github.com/celestix/staticfs/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func AuthMiddleware(publicKey *ecdsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}
		tokenString := parts[1]

		claims, err := utils.VerifyJWT(tokenString, publicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			return
		}

		// Extract route parameters. The route should be defined as "/:team_id/:container_id".
		teamID := c.Param("team_id")
		containerID := c.Param("container_id")

		// Check if the JWT claims match the URL parameters.
		if claims.Id != teamID || claims.ContainerId != containerID {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Next()
	}
}
