package services

import (
	"context"
	"fmt"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type SecretCreator interface {
	CreateSecret(
		ctx context.Context,
		userID int,
		secretType models.SecretType,
		description string,
		encryptedData []byte,
		encryptedKey []byte,
	) (models.Secret, error)
}

type SecretEncryptor interface {
	Encrypt(msg []byte) ([]byte, []byte, error)
}

type Marshaller interface {
	Marshall() ([]byte, error)
}

type CreateSecretService struct {
	creator   SecretCreator
	encryptor SecretEncryptor
}

func NewCreateSecretService(creator SecretCreator, encryptor SecretEncryptor) CreateSecretService {
	return CreateSecretService{
		creator:   creator,
		encryptor: encryptor,
	}
}

func (srv CreateSecretService) Create(
	ctx context.Context,
	userID int,
	description string,
	secretType models.SecretType,
	marshallableSecret Marshaller) (models.Secret, error) {

	secretBytes, err := marshallableSecret.Marshall()
	if err != nil {
		return models.Secret{}, fmt.Errorf("failed to marshal secret: %w", err)
	}
	encryptedMsg, encryptedKey, err := srv.encryptor.Encrypt(secretBytes)
	if err != nil {
		return models.Secret{}, fmt.Errorf("failed to encrypt message: %w", err)
	}
	secret, err := srv.creator.CreateSecret(ctx, userID, secretType, description, encryptedMsg, encryptedKey)
	if err != nil {
		return models.Secret{}, err
	}

	return secret, nil
}
