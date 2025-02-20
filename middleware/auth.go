package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lugvitc/staticfs/utils"
)

func AuthMiddleware(secretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.Query("token")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			return
		}

		claims, err := utils.VerifyJWT(tokenString, secretKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: " + err.Error()})
			return
		}

		c.Set("teamId", claims.Id)
		c.Set("containerId", claims.ContainerId)

		c.Next()
	}
}
