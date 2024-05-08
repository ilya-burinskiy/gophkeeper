package services_test

import (
	"context"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type secretDeleterMock struct{ mock.Mock }

func (m *secretDeleterMock) DeleteSecret(ctx context.Context, secretID int) error {
	args := m.Called(ctx, secretID)
	return args.Error(0)
}

func TestDelete(t *testing.T) {
	testCases := []struct {
		name           string
		userID         int
		secret         models.Secret
		delErr         error
		expectedErrMsg string
	}{
		{
			name:   "deletes secret",
			userID: 1,
			secret: models.Secret{
				ID:         1,
				UserID:     1,
				SecretType: models.CredentialsSecret,
			},
		},
		{
			name:   "returns permission error if user is not secret owner",
			userID: 2,
			secret: models.Secret{
				ID:         1,
				UserID:     1,
				SecretType: models.CredentialsSecret,
			},
			expectedErrMsg: "user with id=2 doesn't have permission to secret with id=1",
		},
	}
	secretDeleter := new(secretDeleterMock)
	delSrv := services.NewDeleteSecretService(secretDeleter)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secretDeleter.On("DeleteSecret", mock.Anything, mock.Anything).
				Return(tc.delErr).
				Once()

			err := delSrv.Delete(context.TODO(), tc.userID, tc.secret)
			if err != nil {
				assert.EqualError(t, err, tc.expectedErrMsg)
			}
		})
	}
}
