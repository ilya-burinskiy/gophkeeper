package services

import (
	"errors"
	"fmt"
)

type ErrNoPermission struct {
	UserID   int
	SecretID int
}

func (err ErrNoPermission) Error() string {
	return fmt.Sprintf(
		"user with id=%d doesn't have permission to secret with id=%d",
		err.UserID,
		err.SecretID,
	)
}

var ErrWrongSecretType = errors.New("can not change secret type")
