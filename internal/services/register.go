package services

import (
	"context"
	"fmt"

	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type UserCreator interface {
	CreateUser(context.Context, string, []byte) (models.User, error)
}

type RegisterService struct {
	usrCreator UserCreator
}

func NewRegisterService(usrCreator UserCreator) RegisterService {
	return RegisterService{
		usrCreator: usrCreator,
	}
}

func (srv RegisterService) Register(ctx context.Context, login string, password string) (string, error) {
	encryptedPassword, err := auth.HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("failed to register user: %w", err)
	}

	user, err := srv.usrCreator.CreateUser(ctx, login, encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("failed to register user: %w", err)
	}

	jwtStr, err := auth.BuildJWTString(user.ID)
	if err != nil {
		return "", fmt.Errorf("failed to register user: %w", err)
	}

	return jwtStr, nil
}
