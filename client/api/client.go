package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

type GophkeeperClient struct {
	baseURL    string
	jwt        string
	httpClient http.Client
}

func NewGophkeeperClient(baseURL string) *GophkeeperClient {
	return &GophkeeperClient{
		baseURL:    baseURL,
		httpClient: http.Client{},
	}
}

func (client *GophkeeperClient) RegisterUser(ctx context.Context, login, password string) error {
	reqBody, err := json.Marshal(
		UserCredentials{
			Login:    login,
			Password: password,
		},
	)
	if err != nil {
		return fmt.Errorf("failed encode request body: %w", err)
	}
	req, err := http.NewRequest(
		http.MethodPost,
		client.baseURL+"/api/user/register",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to register user")
	}

	return nil
}

func (client *GophkeeperClient) AuthenticateUser(ctx context.Context, login, password string) (string, error) {
	reqBody, err := json.Marshal(
		UserCredentials{
			Login:    login,
			Password: password,
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed encode request body: %w", err)
	}
	req, err := http.NewRequest(
		http.MethodPost,
		client.baseURL+"/api/user/login",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to authenticate user")
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "jwt" {
			return cookie.Value, nil
		}
	}

	return "", errors.New("failed to get JWT from response")
}

func (client *GophkeeperClient) GetSecrets(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		client.baseURL+"/api/secrets",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/zip")
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: client.jwt,
	})

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request")
	}
	defer resp.Body.Close()

	archiveContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read archive content: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get secrets status=%d", resp.StatusCode)
	}

	return archiveContent, nil
}

func (client *GophkeeperClient) CreateCredentials(ctx context.Context, login, password string) error {
	reqBody := &bytes.Buffer{}
	writer := multipart.NewWriter(reqBody)
	if err := createFormField(writer, "secret_type", []byte("credentials")); err != nil {
		return fmt.Errorf("failed to add secret_type field: %w", err)
	}
	if err := createFormField(writer, "login", []byte(login)); err != nil {
		return fmt.Errorf("failed to add login field: %w", err)
	}
	if err := createFormField(writer, "password", []byte(password)); err != nil {
		return fmt.Errorf("failed to add password filed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to create request form: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		client.baseURL+"/api/secrets",
		reqBody,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: client.jwt,
	})
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to create creadentials")
	}

	return nil
}

func (client *GophkeeperClient) CreateCreditCard(ctx context.Context, number, name, expiryDateStr, cvv2 string) error {
	reqBody := &bytes.Buffer{}
	writer := multipart.NewWriter(reqBody)
	if err := createFormField(writer, "secret_type", []byte("credit_card_info")); err != nil {
		return fmt.Errorf("failed to add secret_type field: %w", err)
	}
	if err := createFormField(writer, "credit_card_number", []byte(number)); err != nil {
		return fmt.Errorf("failed to add credit_card_number field: %w", err)
	}
	if err := createFormField(writer, "credit_card_name", []byte(name)); err != nil {
		return fmt.Errorf("failed to add credit_card_name field: %w", err)
	}
	if err := createFormField(writer, "credit_card_expiry_date", []byte(expiryDateStr)); err != nil {
		return fmt.Errorf("failed to add credit_card_expirty_date field: %w", err)
	}
	if err := createFormField(writer, "credit_card_cvv2", []byte(cvv2)); err != nil {
		return fmt.Errorf("failed to add credit_card_cvv2 field: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to create request form: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		client.baseURL+"/api/secrets",
		reqBody,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: client.jwt,
	})

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to create credit card")
	}

	return nil
}

func (client *GophkeeperClient) CreateBinData(ctx context.Context, filename string, fileContent []byte) error {
	reqBody := &bytes.Buffer{}
	writer := multipart.NewWriter(reqBody)
	if err := createFormField(writer, "secret_type", []byte("bin_data")); err != nil {
		return fmt.Errorf("failed to add secret_type filed: %w", err)
	}
	fw, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return fmt.Errorf("failed to add file field to form: %w", err)
	}
	_, err = fw.Write(fileContent)
	if err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to create request form: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		client.baseURL+"/api/secrets",
		reqBody,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: client.jwt,
	})

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to create bin data")
	}

	return nil
}

func (client *GophkeeperClient) SetJWT(jwt string) {
	client.jwt = jwt
}

func createFormField(writer *multipart.Writer, name string, value []byte) error {
	fw, err := writer.CreateFormField(name)
	if err != nil {
		return err
	}
	_, err = fw.Write(value)

	return err
}
