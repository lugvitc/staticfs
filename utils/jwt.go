package utils

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type TeamClaims struct {
	Id          string `json:"id"`
	ContainerId string `json:"containerId"`
	jwt.RegisteredClaims
}

func CreateJWT(teamId, containerId string, secretKey *ecdsa.PrivateKey) (string, error) {
	expirationTime := time.Now().Add(time.Hour)
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, TeamClaims{
		Id:          teamId,
		ContainerId: containerId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	})
	tokenString, err := claims.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func VerifyJWT(tokenString string, publicKey *ecdsa.PublicKey) (*TeamClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TeamClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}
	if claims, ok := token.Claims.(*TeamClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}
