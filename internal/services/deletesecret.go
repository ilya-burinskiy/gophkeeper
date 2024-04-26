package services

import (
	"context"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type SecretDeleter interface {
	DeleteSecret(
		ctx context.Context,
		secretID int,
	) error
}

type DeleteSecretService struct {
	secretDeleter SecretDeleter
}

func NewDeleteSecretService(secretDeleter SecretDeleter) DeleteSecretService {
	return DeleteSecretService{
		secretDeleter: secretDeleter,
	}
}

func (srv DeleteSecretService) Delete(ctx context.Context, userID int, secret models.Secret) error {
	if userID != secret.UserID {
		return ErrNoPermission{
			UserID:   userID,
			SecretID: secret.ID,
		}
	}

	return srv.secretDeleter.DeleteSecret(ctx, secret.ID)
}
