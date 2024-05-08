package handlers_test

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type updateServiceMock struct{ mock.Mock }

func (m *updateServiceMock) Update(
	ctx context.Context,
	userID int,
	secret models.Secret,
	newSecretType models.SecretType,
	description string,
	marshallableSecret services.Marshaller,
	encryptedKey []byte) error {

	args := m.Called(ctx, userID, secret, newSecretType, description, marshallableSecret, encryptedKey)
	return args.Error(0)
}

func TestUpdateCredentials(t *testing.T) {
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
		login     string
		password  string
		findRes   findResult
		updateErr error
		want      want
	}{
		{
			name:     "responds with ok status",
			secretID: 1,
			login:    "login",
			password: "password",
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
			name:     "responds with forbidden status",
			secretID: 1,
			login:    "login",
			password: "password",
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					UserID:     2,
					SecretType: models.CredentialsSecret,
				},
			},
			updateErr: services.ErrNoPermission{
				SecretID: 1,
				UserID:   2,
			},
			want: want{
				code: http.StatusForbidden,
			},
		},
		{
			name:     "responds with internal server error",
			secretID: 1,
			login:    "login",
			password: "password",
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					UserID:     1,
					SecretType: models.CredentialsSecret,
				},
			},
			updateErr: errors.New("error"),
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
	findSrv := new(findSecretServiceMock)
	updateSrv := new(updateServiceMock)
	handler := http.HandlerFunc(
		handlers.NewSecretHandler(zaptest.NewLogger(t)).
			Update(findSrv, updateSrv),
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findCall := findSrv.On("Find", mock.Anything, mock.Anything).
				Return(tc.findRes.secret, tc.findRes.err)
			defer findCall.Unset()
			updateCall := updateSrv.
				On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(tc.updateErr)
			defer updateCall.Unset()

			reqBody := bytes.Buffer{}
			writer := multipart.NewWriter(&reqBody)
			createFormField(t, writer, "secret_type", []byte("credentials"))
			createFormField(t, writer, "login", []byte(tc.login))
			createFormField(t, writer, "password", []byte(tc.password))
			err = writer.Close()
			require.NoError(t, err)

			request, err := http.NewRequest(
				http.MethodPut,
				"/api/secrets/"+strconv.Itoa(tc.secretID),
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", strconv.Itoa(tc.secretID))
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func TestUpdateCreditCard(t *testing.T) {
	type want struct {
		code     int
		response string
	}
	type findResult struct {
		secret models.Secret
		err    error
	}
	testCases := []struct {
		name       string
		secretID   int
		number     string
		ownerName  string
		expiryDate string
		cvv2       string
		findRes    findResult
		updateErr  error
		want       want
	}{
		{
			name:       "responds with ok status",
			secretID:   1,
			number:     "1234 5678 9101 1121",
			ownerName:  "Name Name",
			expiryDate: "2025-10-02T15:00:00Z",
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.CreditCardSecret,
					UserID:     1,
				},
			},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:       "responds with forbidden status",
			secretID:   1,
			number:     "1234 5678 9101 1121",
			ownerName:  "Name Name",
			expiryDate: "2025-10-02T15:00:00Z",
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.CreditCardSecret,
					UserID:     2,
				},
			},
			updateErr: services.ErrNoPermission{
				SecretID: 1,
				UserID:   2,
			},
			want: want{
				code: http.StatusForbidden,
			},
		},
		{
			name:       "responds with internal server error",
			secretID:   1,
			number:     "1234 5678 9101 1121",
			ownerName:  "Name Name",
			expiryDate: "2025-10-02T15:00:00Z",
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.CreditCardSecret,
					UserID:     1,
				},
			},
			updateErr: errors.New("error"),
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
	findSrv := new(findSecretServiceMock)
	updateSrv := new(updateServiceMock)
	handler := http.HandlerFunc(
		handlers.NewSecretHandler(zaptest.NewLogger(t)).
			Update(findSrv, updateSrv),
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findCall := findSrv.On("Find", mock.Anything, mock.Anything).
				Return(tc.findRes.secret, tc.findRes.err)
			defer findCall.Unset()
			updateCall := updateSrv.
				On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(tc.updateErr)
			defer updateCall.Unset()

			reqBody := bytes.Buffer{}
			writer := multipart.NewWriter(&reqBody)
			createFormField(t, writer, "secret_type", []byte("credit_card_info"))
			createFormField(t, writer, "credit_card_number", []byte(tc.number))
			createFormField(t, writer, "credit_card_name", []byte(tc.ownerName))
			createFormField(t, writer, "credit_card_expiry_date", []byte(tc.expiryDate))
			createFormField(t, writer, "credit_card_cvv2", []byte(tc.cvv2))
			err = writer.Close()
			require.NoError(t, err)

			request, err := http.NewRequest(
				http.MethodPut,
				"/api/secrets/"+strconv.Itoa(tc.secretID),
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", strconv.Itoa(tc.secretID))
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func TestUpdateBinData(t *testing.T) {
	type want struct {
		code     int
		response string
	}
	type findResult struct {
		secret models.Secret
		err    error
	}
	testCases := []struct {
		name        string
		secretID    int
		fileContent []byte
		findRes     findResult
		updateErr   error
		want        want
	}{
		{
			name:        "responds with ok status",
			secretID:    1,
			fileContent: []byte{0x1, 0x2, 0x3},
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.BinDataSecret,
					UserID:     1,
				},
			},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:        "responds with forbidden status",
			fileContent: []byte{0x1, 0x2, 0x3},
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.CreditCardSecret,
					UserID:     2,
				},
			},
			updateErr: services.ErrNoPermission{
				SecretID: 1,
				UserID:   2,
			},
			want: want{
				code: http.StatusForbidden,
			},
		},
		{
			name:        "responds with internal server error",
			fileContent: []byte{0x1, 0x2, 0x3},
			findRes: findResult{
				secret: models.Secret{
					ID:         1,
					SecretType: models.CreditCardSecret,
					UserID:     1,
				},
			},
			updateErr: errors.New("error"),
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
	findSrv := new(findSecretServiceMock)
	updateSrv := new(updateServiceMock)
	handler := http.HandlerFunc(
		handlers.NewSecretHandler(zaptest.NewLogger(t)).
			Update(findSrv, updateSrv),
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findCall := findSrv.On("Find", mock.Anything, mock.Anything).
				Return(tc.findRes.secret, tc.findRes.err)
			defer findCall.Unset()
			updateCall := updateSrv.
				On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(tc.updateErr)
			defer updateCall.Unset()

			reqBody := bytes.Buffer{}
			writer := multipart.NewWriter(&reqBody)
			createFormField(t, writer, "secret_type", []byte("bin_data"))
			fw, err := writer.CreateFormFile("file", "file")
			require.NoError(t, err)
			_, err = fw.Write(tc.fileContent)
			require.NoError(t, err)
			err = writer.Close()
			require.NoError(t, err)
			err = writer.Close()
			require.NoError(t, err)

			request, err := http.NewRequest(
				http.MethodPut,
				"/api/secrets/"+strconv.Itoa(tc.secretID),
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", strconv.Itoa(tc.secretID))
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}

}
