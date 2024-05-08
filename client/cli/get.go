package cli

import (
	"context"
	"fmt"
	"os"
)

type SecretFetcher interface {
	GetSecrets(ctx context.Context) ([]byte, error)
	SetJWT(jwt string)
}

type GetSecretsCmd struct {
	fetcher SecretFetcher
}

func NewGetSecretCmd(fetcher SecretFetcher) GetSecretsCmd {
	return GetSecretsCmd{
		fetcher: fetcher,
	}
}

func (getCmd GetSecretsCmd) Execute(archiveFilename, jwt string) error {
	getCmd.fetcher.SetJWT(jwt)
	archiveContent, err := getCmd.fetcher.GetSecrets(context.TODO())
	if err != nil {
		return err
	}
	err = os.WriteFile(archiveFilename, archiveContent, 0666)
	if err != nil {
		return fmt.Errorf("failed to save archive: %w", err)
	}

	return nil
}
