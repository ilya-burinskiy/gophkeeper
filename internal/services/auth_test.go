package services_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type userFinder struct{ mock.Mock }

func (f *userFinder) FindUserByLogin(ctx context.Context, login string) (models.User, error) {
	args := f.Called(ctx, login)
	return args.Get(0).(models.User), args.Error(1)
}

func TestAuthenticate(t *testing.T) {
	type want struct {
		jwtStr string
		errMsg string
	}
	type findUserResult struct {
		user models.User
		err  error
	}
	usrFinder := new(userFinder)
	authSrv := services.NewAuthenticateService(usrFinder)
	testCases := []struct {
		name     string
		login    string
		password string
		findRes  findUserResult
		want     want
	}{
		{
			name:     "return JWT string",
			login:    "login",
			password: "password",
			findRes: findUserResult{
				user: models.User{
					ID:                1,
					Login:             "login",
					EncryptedPassword: hashPassword(t, "password"),
				},
			},
			want: want{
				jwtStr: buildJWTString(t, 1),
			},
		},
		{
			name:     "returns eror if failed to find user",
			login:    "login",
			password: "password",
			findRes: findUserResult{
				err: errors.New("error"),
			},
			want: want{errMsg: "failed to authenticate user: error"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.TODO()
			findCall := usrFinder.On("FindUserByLogin", mock.Anything, mock.Anything).
				Return(tc.findRes.user, tc.findRes.err)
			defer findCall.Unset()

			jwtStr, err := authSrv.Authenticate(ctx, tc.login, tc.password)
			if err == nil {
				assert.Equal(
					t,
					userIDFromJWT(t, tc.want.jwtStr),
					userIDFromJWT(t, jwtStr),
				)
			} else {
				assert.EqualError(t, err, tc.want.errMsg)
			}
		})
	}
}

func hashPassword(t *testing.T, pwd string) []byte {
	bytes, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	require.NoError(t, err)

	return bytes
}
