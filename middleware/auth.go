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

		c.Set("teamId", claims.Id)
		c.Set("containerId", claims.ContainerId)

		c.Next()
	}
}
