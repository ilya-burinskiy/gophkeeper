package handlers_test

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type createServiceMock struct{ mock.Mock }

func (m *createServiceMock) Create(
	ctx context.Context,
	userID int,
	description string,
	secretType models.SecretType,
	marshallableSecret services.Marshaller) (models.Secret, error) {

	args := m.Called(ctx, userID, description, secretType, marshallableSecret)
	return args.Get(0).(models.Secret), args.Error(1)
}

func TestCreateCredentials(t *testing.T) {
	type createResult struct {
		secret models.Secret
		err    error
	}
	type want struct {
		code     int
		response string
	}
	userID := 1
	jwtStr, err := auth.BuildJWTString(userID)
	require.NoError(t, err)
	authCookie := &http.Cookie{
		Name:  "jwt",
		Value: jwtStr,
	}
	testCases := []struct {
		name        string
		userID      int
		description string
		login       string
		password    string
		createRes   createResult
		want        want
	}{
		{
			name:        "responds with ok status",
			userID:      userID,
			description: "description",
			login:       "login",
			password:    "password",
			createRes: createResult{
				secret: models.Secret{ID: 1},
			},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:        "responds with internal server error",
			userID:      userID,
			description: "description",
			login:       "login",
			password:    "password",
			createRes: createResult{
				err: errors.New("error"),
			},
			want: want{
				code: http.StatusInternalServerError,
			},
		},
	}
	logger := zaptest.NewLogger(t)
	createSrv := new(createServiceMock)
	handler := http.HandlerFunc(
		handlers.
			NewSecretHandler(logger).
			Create(createSrv),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			createSrv.
				On("Create",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything).
				Return(tc.createRes.secret, tc.createRes.err).
				Once()

			reqBody := bytes.Buffer{}
			writer := multipart.NewWriter(&reqBody)
			createFormField(t, writer, "secret_type", []byte("credentials"))
			createFormField(t, writer, "loging", []byte(tc.login))
			createFormField(t, writer, "password", []byte(tc.password))
			err = writer.Close()
			require.NoError(t, err)

			request, err := http.NewRequest(
				http.MethodPost,
				"/api/secrets",
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func TestCreateCreditCard(t *testing.T) {
	type createResult struct {
		secret models.Secret
		err    error
	}
	type want struct {
		code     int
		response string
	}
	userID := 1
	jwtStr, err := auth.BuildJWTString(userID)
	require.NoError(t, err)
	authCookie := &http.Cookie{
		Name:  "jwt",
		Value: jwtStr,
	}
	testCases := []struct {
		name        string
		userID      int
		description string
		number      string
		ownerName   string
		expiryDate  string
		cvv2        string
		createRes   createResult
		want        want
	}{
		{
			name:        "responds with ok status",
			userID:      userID,
			description: "description",
			number:      "1234 5678 9101 1121",
			ownerName:   "Name Name",
			expiryDate:  "2025-10-02T15:00:00Z",
			cvv2:        "123",
			createRes: createResult{
				secret: models.Secret{ID: 1},
			},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:        "responds with internal server error",
			userID:      userID,
			description: "description",
			number:      "1234 5678 9101 1121",
			ownerName:   "Name Name",
			expiryDate:  "2025-10-02T15:00:00Z",
			cvv2:        "123",
			createRes: createResult{
				err: errors.New("error"),
			},
			want: want{
				code: http.StatusInternalServerError,
			},
		},
	}
	logger := zaptest.NewLogger(t)
	createSrv := new(createServiceMock)
	handler := http.HandlerFunc(
		handlers.
			NewSecretHandler(logger).
			Create(createSrv),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			createSrv.
				On("Create",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything).
				Return(tc.createRes.secret, tc.createRes.err).
				Once()

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
				http.MethodPost,
				"/api/secrets",
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func TestCreateBinData(t *testing.T) {
	type createResult struct {
		secret models.Secret
		err    error
	}
	type want struct {
		code     int
		response string
	}
	userID := 1
	jwtStr, err := auth.BuildJWTString(userID)
	require.NoError(t, err)
	authCookie := &http.Cookie{
		Name:  "jwt",
		Value: jwtStr,
	}
	testCases := []struct {
		name        string
		userID      int
		fileContent []byte
		createRes   createResult
		want        want
	}{
		{
			name:   "responds with ok status",
			userID: userID,
			createRes: createResult{
				secret: models.Secret{ID: 1},
			},
			fileContent: []byte{0x1, 0x2, 0x3},
			want: want{
				code: http.StatusOK,
			},
		},
		{
			name:   "responds with internal server error",
			userID: userID,
			createRes: createResult{
				err: errors.New("error"),
			},
			want: want{
				code: http.StatusInternalServerError,
			},
		},
	}
	logger := zaptest.NewLogger(t)
	createSrv := new(createServiceMock)
	handler := http.HandlerFunc(
		handlers.
			NewSecretHandler(logger).
			Create(createSrv),
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			createSrv.
				On("Create",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything).
				Return(tc.createRes.secret, tc.createRes.err).
				Once()

			reqBody := bytes.Buffer{}
			writer := multipart.NewWriter(&reqBody)
			createFormField(t, writer, "secret_type", []byte("bin_data"))
			fw, err := writer.CreateFormFile("file", "file")
			require.NoError(t, err)
			_, err = fw.Write(tc.fileContent)
			require.NoError(t, err)
			err = writer.Close()
			require.NoError(t, err)

			request, err := http.NewRequest(
				http.MethodPost,
				"/api/secrets",
				&reqBody,
			)
			require.NoError(t, err)
			request.AddCookie(authCookie)
			request.Header.Add("Content-Type", writer.FormDataContentType())

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assert.Equal(t, tc.want.code, recorder.Result().StatusCode)
			assert.Equal(t, tc.want.response, recorder.Body.String())
		})
	}
}

func createFormField(t *testing.T, writer *multipart.Writer, name string, value []byte) {
	fw, err := writer.CreateFormField(name)
	require.NoError(t, err)
	_, err = fw.Write(value)
	require.NoError(t, err)
}
