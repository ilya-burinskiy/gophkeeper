package handlers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type secretFetcherMock struct{ mock.Mock }

func (m *secretFetcherMock) FetchUserSecrets(ctx context.Context, userID int) ([]byte, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]byte), args.Error(1)
}

func TestGetUserHandler(t *testing.T) {
	type want struct {
		code     int
		response []byte
	}
	type fetchResult struct {
		archiveContent []byte
		err            error
	}
	testCases := []struct {
		name     string
		fetchRes fetchResult
		want     want
	}{
		{
			name: "responds with ok status",
			fetchRes: fetchResult{
				archiveContent: []byte{0x1, 0x2, 0x3},
			},
			want: want{
				code:     http.StatusOK,
				response: []byte{0x1, 0x2, 0x3},
			},
		},
		{
			name: "responds with internal server error",
			fetchRes: fetchResult{
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
	fetchSrv := new(secretFetcherMock)
	handler := http.HandlerFunc(
		handlers.NewSecretHandler(zaptest.NewLogger(t)).
			GetUserSecrets(fetchSrv),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fetchCall := fetchSrv.On("FetchUserSecrets", mock.Anything, mock.Anything).
				Return(tc.fetchRes.archiveContent, tc.fetchRes.err)
			defer fetchCall.Unset()

			request, err := http.NewRequest(
				http.MethodGet,
				"/api/secrets",
				nil,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.Bytes())
		})
	}
}
