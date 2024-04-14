package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type registerService struct{ mock.Mock }

func (srv *registerService) Register(ctx context.Context, login, password string) (string, error) {
	args := srv.Called(ctx, login, password)
	return args.String(0), args.Error(1)
}

func TestRegister(t *testing.T) {
	type want struct {
		code     int
		response string
	}
	type registerResult struct {
		jwtStr string
		err    error
	}
	testCases := []struct {
		name        string
		requestBody []byte
		registerRes registerResult
		want        want
	}{
		{
			name:        "responses with ok status",
			requestBody: toJSON(t, map[string]string{"login": "login", "password": "password"}),
			registerRes: registerResult{jwtStr: "123"},
			want:        want{code: http.StatusOK},
		},
		{
			name:        "responses with bad request status if request body is invalid",
			requestBody: toJSON(t, "login: login, password: password"),
			want: want{
				code:     http.StatusBadRequest,
				response: "\"invalid request body\"\n",
			},
		},
		{
			name:        "responses with status conflict if user already registered",
			requestBody: toJSON(t, map[string]string{"login": "login", "password": "password"}),
			registerRes: registerResult{
				err: storage.ErrUserNotUniq{User: models.User{ID: 1, Login: "login"}},
			},
			want: want{
				code:     http.StatusConflict,
				response: string(toJSON(t, "user with login \"login\" already exists")) + "\n",
			},
		},
		{
			name:        "responses with internal server error status",
			requestBody: toJSON(t, map[string]string{"login": "login", "password": "password"}),
			registerRes: registerResult{
				err: errors.New("error"),
			},
			want: want{
				code: http.StatusInternalServerError,
				response: string(toJSON(t, "error")) + "\n",
			},
		},
	}

	regService := new(registerService)
	handler := http.HandlerFunc(
		handlers.NewUserHandlers(zaptest.NewLogger(t)).
			Register(regService),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			regCall := regService.On("Register", mock.Anything, mock.Anything, mock.Anything).
				Return(tc.registerRes.jwtStr, tc.registerRes.err)
			defer regCall.Unset()

			recorder := httptest.NewRecorder()
			request, err := http.NewRequest(
				http.MethodPost,
				"/api/user/register",
				bytes.NewReader(tc.requestBody),
			)
			require.NoError(t, err)
			handler.ServeHTTP(recorder, request)
			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func toJSON(t *testing.T, val interface{}) []byte {
	result, err := json.Marshal(val)
	require.NoError(t, err)

	return result
}
