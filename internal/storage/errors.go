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
