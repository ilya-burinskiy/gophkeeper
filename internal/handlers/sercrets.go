package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/ilya-burinskiy/gophkeeper/internal/middlewares"
	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"go.uber.org/zap"
)

type CreateSecretService interface {
	Create(
		ctx context.Context,
		userID int,
		description string,
		secretType models.SecretType,
		marshallableSecret services.Marshaller,
	) (models.Secret, error)
}

type SecretHandler struct {
	logger *zap.Logger
}

func NewSecretHandler(logger *zap.Logger) SecretHandler {
	return SecretHandler{
		logger: logger,
	}
}

func (h SecretHandler) Create(srv CreateSecretService) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(1 << 30)
		userID, _ := middlewares.UserIDFromContext(r.Context())
		description := r.FormValue("description")
		var status int
		switch r.FormValue("secret_type") {
		case "credentials":
			status = h.handleCreateCredsSecret(
				r.Context(),
				userID,
				description,
				r.FormValue("login"),
				r.FormValue("password"),
				srv,
			)
		case "credit_card_info":
			status = h.handlerCreateCreditCardSecret(
				r.Context(),
				userID,
				description,
				r.FormValue("credit_card_number"),
				r.FormValue("credit_card_name"),
				r.FormValue("credit_card_expiry_date"),
				r.FormValue("credit_card_cvv2"),
				srv,
			)
		case "bin_data":
			status = h.handleCreateBinDataSecret(
				userID,
				description,
				r,
				srv,
			)
		default:
			status = http.StatusBadRequest
		}
		w.WriteHeader(status)
	}
}

func (h SecretHandler) handleCreateCredsSecret(
	ctx context.Context,
	userID int,
	description,
	login,
	password string,
	createSrv CreateSecretService) int {

	_, err := createSrv.Create(
		ctx,
		userID,
		description,
		models.CredentialsSecret,
		&models.Credentials{
			Login:    login,
			Password: password,
		},
	)
	if err != nil {
		h.logger.Info("failed to create secret", zap.Error(err))
		return http.StatusInternalServerError
	}

	return http.StatusOK
}

func (h SecretHandler) handlerCreateCreditCardSecret(
	ctx context.Context,
	userID int,
	description,
	number,
	name,
	expiryDateStr,
	cvv2 string,
	createSrv CreateSecretService) int {

	expDate, err := time.Parse(time.RFC3339, expiryDateStr)
	if err != nil {
		h.logger.Info("failed to parse date", zap.String("credit_card_expiry_date", expiryDateStr), zap.Error(err))
		return http.StatusBadRequest
	}

	_, err = createSrv.Create(
		ctx,
		userID,
		description,
		models.CreditCardSecret,
		&models.CreditCard{
			Number:     number,
			Name:       name,
			ExpiryDate: expDate,
			CVV2:       cvv2,
		},
	)
	if err != nil {
		h.logger.Info("failed save credit card secret", zap.Error(err))
		return http.StatusInternalServerError
	}

	return http.StatusOK
}

func (h SecretHandler) handleCreateBinDataSecret(
	userID int,
	description string,
	r *http.Request,
	srv CreateSecretService) int {

	file, header, err := r.FormFile("file")
	if err != nil {
		h.logger.Info("failed to get file", zap.Error(err))
		return http.StatusBadRequest
	}
	defer func() {
		if err := file.Close(); err != nil {
			h.logger.Info("failed to close file", zap.Error(err))
		}
	}()
	if header.Size > 1<<30 {
		h.logger.Info("too large file")
		return http.StatusBadRequest
	}

	fileContent := bytes.NewBuffer(nil)
	if _, err := io.Copy(fileContent, file); err != nil {
		h.logger.Info("failed to copy file content", zap.Error(err))
		return http.StatusInternalServerError
	}
	_, err = srv.Create(
		r.Context(),
		userID,
		description,
		models.BinDataSecret,
		&models.BinData{Bytes: fileContent.Bytes()},
	)
	if err != nil {
		h.logger.Info("failed to create binary data secret", zap.Error(err))
		return http.StatusInternalServerError
	}

	return http.StatusOK
}
