package services

import (
	"context"
	"fmt"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type SecretUpdater interface {
	UpdateSecret(
		ctx context.Context,
		id int,
		description string,
		newData []byte) error
}

type ReEncryptor interface {
	ReEncrypt(msg []byte, key []byte) ([]byte, error)
}

type UpdateSecretService struct {
	updater     SecretUpdater
	reEncryptor ReEncryptor
}

func NewUpdateSecretService(updater SecretUpdater, reEncryptor ReEncryptor) UpdateSecretService {
	return UpdateSecretService{
		updater:     updater,
		reEncryptor: reEncryptor,
	}
}

func (srv UpdateSecretService) Update(
	ctx context.Context,
	userID int,
	secret models.Secret,
	newSecretType models.SecretType,
	newDescription string,
	marshallableSecret Marshaller,
	key []byte) error {

	if userID != secret.UserID {
		return ErrNoPermission{UserID: userID, SecretID: secret.ID}
	}
	if secret.SecretType != newSecretType {
		return ErrWrongSecretType
	}

	secretBytes, err := marshallableSecret.Marshall()
	if err != nil {
		return fmt.Errorf("failed to mashall secreet: %w", err)
	}
	encryptedMsg, err := srv.reEncryptor.ReEncrypt(secretBytes, key)
	if err != nil {
		return fmt.Errorf("failed to reencrypt secret: %w", err)
	}

	return srv.updater.UpdateSecret(ctx, secret.ID, newDescription, encryptedMsg)
}
