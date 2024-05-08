package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type secretCreatorMock struct{ mock.Mock }

func (m *secretCreatorMock) CreateSecret(
	ctx context.Context,
	userID int,
	secretType models.SecretType,
	description string,
	encryptedData []byte,
	encryptedKey []byte) (models.Secret, error) {

	args := m.Called(ctx, userID, secretType, description, encryptedData, encryptedKey)
	return args.Get(0).(models.Secret), args.Error(1)
}

type secretEncryptorMock struct{ mock.Mock }

func (m *secretEncryptorMock) Encrypt(msg []byte) ([]byte, []byte, error) {
	args := m.Called(msg)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func TestCreateSecret(t *testing.T) {
	type createResult struct {
		secret models.Secret
		err    error
	}
	type encryptorResult struct {
		encryptedData []byte
		encryptedKey  []byte
		err           error
	}
	type want struct {
		secret   models.Secret
		errorMsg string
	}
	secretCreator := new(secretCreatorMock)
	encryptor := new(secretEncryptorMock)
	createSrv := services.NewCreateSecretService(secretCreator, encryptor)
	testCases := []struct {
		name               string
		userID             int
		description        string
		secretType         models.SecretType
		marshallableSecret services.Marshaller
		encryptorRes       encryptorResult
		createRes          createResult
		want               want
	}{
		{
			name:        "creates secret",
			userID:      1,
			description: "description",
			secretType:  models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "login",
				Password: "password",
			},
			encryptorRes: encryptorResult{
				encryptedData: []byte{1, 2, 3},
				encryptedKey:  []byte{4, 5, 6},
			},
			createRes: createResult{
				secret: models.Secret{
					ID:            1,
					UserID:        1,
					SecretType:    models.CredentialsSecret,
					Description:   "description",
					EncryptedData: []byte{1, 2, 3},
					EncryptedKey:  []byte{4, 5, 6},
				},
			},
			want: want{
				secret: models.Secret{
					ID:            1,
					UserID:        1,
					SecretType:    models.CredentialsSecret,
					Description:   "description",
					EncryptedData: []byte{1, 2, 3},
					EncryptedKey:  []byte{4, 5, 6},
				},
			},
		},
		{
			name:        "returns error if could not encrypt marshalled secret",
			userID:      1,
			description: "description",
			secretType:  models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "login",
				Password: "password",
			},
			encryptorRes: encryptorResult{
				err: errors.New("error"),
			},
			want: want{
				errorMsg: "failed to encrypt message: error",
			},
		},
		{
			name:        "return error if could not save secret",
			userID:      1,
			description: "description",
			secretType:  models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "login",
				Password: "password",
			},
			encryptorRes: encryptorResult{
				encryptedData: []byte{1, 2, 3},
				encryptedKey:  []byte{4, 5, 6},
			},
			createRes: createResult{
				err: errors.New("error"),
			},
			want: want{
				errorMsg: "error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptor.
				On("Encrypt", mock.Anything).
				Return(tc.encryptorRes.encryptedData,
					tc.encryptorRes.encryptedKey,
					tc.encryptorRes.err).
				Once()
			secretCreator.
				On("CreateSecret",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything).
				Return(tc.createRes.secret, tc.createRes.err).
				Once()
			secret, err := createSrv.Create(
				context.TODO(),
				tc.userID,
				tc.description,
				tc.secretType,
				tc.marshallableSecret,
			)
			if err == nil {
				assert.Equal(t, tc.want.secret, secret)
			} else {
				assert.EqualError(t, err, tc.want.errorMsg)
			}
		})
	}
}
