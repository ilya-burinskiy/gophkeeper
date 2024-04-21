package storage

import (
	"fmt"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type ErrUserNotUniq struct {
	User models.User
}

func (err ErrUserNotUniq) Error() string {
	return fmt.Sprintf("user with login \"%s\" already exists", err.User.Login)
}

type ErrUserNotFound struct {
	User models.User
}

func (err ErrUserNotFound) Error() string {
	return fmt.Sprintf("user with login \"%s\" not found", err.User.Login)
}

type ErrSecretNotFound struct {
	Secret models.Secret
}

func (err ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret with id=%d not found", err.Secret.ID)
}
