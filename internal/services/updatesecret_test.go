package services_test

import (
	"errors"
	"context"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type secretUpdaterMock struct{ mock.Mock }

func (m *secretUpdaterMock) UpdateSecret(
	ctx context.Context,
	id int,
	description string,
	newData []byte) error {

	args := m.Called(ctx, id, description, newData)
	return args.Error(0)
}

type reEncryptorMock struct{ mock.Mock }

func (m *reEncryptorMock) ReEncrypt(msg []byte, key []byte) ([]byte, error) {
	args := m.Called(msg, key)
	return args.Get(0).([]byte), args.Error(1)
}

func TestUpdate(t *testing.T) {
	type reEncryptResult struct {
		encryptedMsg []byte
		err          error
	}
	testCases := []struct {
		name               string
		userID             int
		secret             models.Secret
		newSecretType      models.SecretType
		newDescription     string
		marshallableSecret services.Marshaller
		encryptedKey       []byte
		reEncryptRes       reEncryptResult
		updateErr          error
		expectedErrorMsg   string
	}{
		{
			name:          "updates secret",
			userID:        1,
			secret:        models.Secret{ID: 1, UserID: 1, SecretType: models.CredentialsSecret},
			newSecretType: models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "new_login",
				Password: "new_password",
			},
			encryptedKey: []byte{0x4, 0x5, 0x6},
			reEncryptRes: reEncryptResult{
				encryptedMsg: []byte{0x1, 0x2, 0x3},
			},
		},
		{
			name:             "returns error if current user is not secret owner",
			userID:           1,
			secret:           models.Secret{ID: 1, UserID: 2, SecretType: models.CredentialsSecret},
			expectedErrorMsg: "user with id=1 doesn't have permission to secret with id=1",
		},
		{
			name:               "return error if user trying to change secret type",
			userID:             1,
			secret:             models.Secret{ID: 1, UserID: 1, SecretType: models.CredentialsSecret},
			newSecretType:      models.CreditCardSecret,
			marshallableSecret: &models.CreditCard{},
			expectedErrorMsg:   "can not change secret type",
		},
		{
			name: "returns error if could not reencrypt secret",
			userID:        1,
			secret:        models.Secret{ID: 1, UserID: 1, SecretType: models.CredentialsSecret},
			newSecretType: models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "new_login",
				Password: "new_password",
			},
			encryptedKey: []byte{0x4, 0x5, 0x6},
			reEncryptRes: reEncryptResult{
				err: errors.New("error"),
			},
			expectedErrorMsg: "failed to reencrypt secret: error",
		},
		{
			name: "return error if could not save secret",
			userID:        1,
			secret:        models.Secret{ID: 1, UserID: 1, SecretType: models.CredentialsSecret},
			newSecretType: models.CredentialsSecret,
			marshallableSecret: &models.Credentials{
				Login:    "new_login",
				Password: "new_password",
			},
			encryptedKey: []byte{0x4, 0x5, 0x6},
			reEncryptRes: reEncryptResult{
				encryptedMsg: []byte{0x1, 0x2, 0x3},
			},
			updateErr: errors.New("error"),
			expectedErrorMsg: "error",
		},
	}

	encryptor := new(reEncryptorMock)
	updater := new(secretUpdaterMock)
	updateSrv := services.NewUpdateSecretService(updater, encryptor)
	for _, tc := range testCases {
		encryptor.On("ReEncrypt", mock.Anything, mock.Anything).
			Return(tc.reEncryptRes.encryptedMsg, tc.reEncryptRes.err).
			Once()
		updater.On("UpdateSecret", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(tc.updateErr).
			Once()

		t.Run(tc.name, func(t *testing.T) {
			err := updateSrv.Update(
				context.TODO(),
				tc.userID,
				tc.secret,
				tc.newSecretType,
				tc.newDescription,
				tc.marshallableSecret,
				tc.encryptedKey,
			)
			if err != nil {
				assert.EqualError(t, err, tc.expectedErrorMsg)
			}
		})
	}
}
