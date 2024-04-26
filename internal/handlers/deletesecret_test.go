package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/ilya-burinskiy/gophkeeper/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type findSecretServiceMock struct{ mock.Mock }

func (m *findSecretServiceMock) Find(ctx context.Context, secretID int) (models.Secret, error) {
	args := m.Called(ctx, secretID)
	return args.Get(0).(models.Secret), args.Error(1)
}

type deleteServiceMock struct{ mock.Mock }

func (m *deleteServiceMock) Delete(ctx context.Context, userID int, secret models.Secret) error {
	args := m.Called(ctx, userID, secret)
	return args.Error(0)
}

func TestDelete(t *testing.T) {
	type want struct {
		code     int
		response string
	}
	type findResult struct {
		secret models.Secret
		err    error
	}
	testCases := []struct {
		name      string
		secretID  int
		findRes   findResult
		deleteErr error
		want      want
	}{
		{
			name:     "responds with ok status",
			secretID: 1,
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					UserID:     1,
					SecretType: models.CredentialsSecret,
				},
			},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:     "responds with status not found",
			secretID: 1,
			findRes: findResult{
				err: storage.ErrSecretNotFound{Secret: models.Secret{ID: 1}},
			},
			want: want{
				code: http.StatusNotFound,
			},
		},
		{
			name:     "responds with forbidden status if user has not permissions",
			secretID: 1,
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					UserID:     2,
					SecretType: models.CredentialsSecret,
				},
			},
			deleteErr: services.ErrNoPermission{SecretID: 1, UserID: 2},
			want: want{
				code: http.StatusForbidden,
			},
		},
		{
			name:     "responds with internal server error status",
			secretID: 1,
			findRes: findResult{
				err: errors.New("error"),
			},
			want: want{
				code: http.StatusInternalServerError,
			},
		},
	}

	userID := 1
	jwtStr, err := auth.BuildJWTString(userID)
	require.NoError(t, err)
	authCookie := &http.Cookie{
		Name:  "jwt",
		Value: jwtStr,
	}
	delSrv := new(deleteServiceMock)
	findSrv := new(findSecretServiceMock)
	handler := http.HandlerFunc(
		handlers.NewSecretHandler(zaptest.NewLogger(t)).
			Delete(findSrv, delSrv),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findCall := findSrv.On("Find", mock.Anything, mock.Anything).
				Return(tc.findRes.secret, tc.findRes.err).
				Once()
			defer findCall.Unset()
			delCall := delSrv.On("Delete", mock.Anything, mock.Anything, mock.Anything).
				Return(tc.deleteErr).
				Once()
			defer delCall.Unset()

			request, err := http.NewRequest(
				http.MethodDelete,
				"/api/secrets/"+strconv.Itoa(tc.secretID),
				nil,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", strconv.Itoa(tc.secretID))
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}
