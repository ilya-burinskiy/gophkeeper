package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type UserFinder interface {
	FindUserByLogin(ctx context.Context, login string) (models.User, error)
}

type AuthenticateService struct {
	userFinder UserFinder
}

func NewAuthenticateService(usrFinder UserFinder) AuthenticateService {
	return AuthenticateService{
		userFinder: usrFinder,
	}
}

func (srv AuthenticateService) Authenticate(ctx context.Context, login, password string) (string, error) {
	user, err := srv.userFinder.FindUserByLogin(ctx, login)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate user: %w", err)
	}

	if !auth.ValidatePasswordHash(password, string(user.EncryptedPassword)) {
		return "", errors.New("invalid login or password")
	}

	jwtStr, err := auth.BuildJWTString(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate user: %w", err)
	}

	return jwtStr, nil
}
