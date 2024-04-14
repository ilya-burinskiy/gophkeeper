package services_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/configs"
	"github.com/stretchr/testify/require"
)

func userIDFromJWT(t *testing.T, jwtStr string) int {
	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(jwtStr, claims, func(tok *jwt.Token) (interface{}, error) {
		return []byte(configs.SecretKey), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	return claims.UserID
}
