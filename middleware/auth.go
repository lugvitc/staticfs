package middleware

import (
	"crypto/ecdsa"
	"github.com/celestix/staticfs/utils"
	"github.com/gin-gonic/gin"
	"net/http"
)

func AuthMiddleware(publicKey *ecdsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Query("token")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			return
		}

		claims, err := utils.VerifyJWT(tokenString, publicKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			return
		}

		// Extract route parameters. The route is "/:team_id/:container_id/*filepath".
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
