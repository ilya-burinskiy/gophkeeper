package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type GophkeeperClient struct {
	baseURL    string
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
