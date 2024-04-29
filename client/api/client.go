package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (client *GophkeeperClient) SetJWT(jwt string) {
	client.jwt = jwt
}
