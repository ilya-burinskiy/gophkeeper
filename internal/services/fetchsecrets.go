package services

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"strconv"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type UserSecretsFetcher interface {
	ListUserSecrets(ctx context.Context, userID int) ([]models.Secret, error)
}

type Unmarshaller interface {
	Unmarshall(bs []byte) error
}

type Decryptor interface {
	Decrypt(ciphertext []byte, encryptedKey []byte) ([]byte, error)
}

type FetchUserSecretsService struct {
	fetcher   UserSecretsFetcher
	decryptor Decryptor
}

func NewFetchUserSecretsService(fetcher UserSecretsFetcher, decryptor Decryptor) FetchUserSecretsService {
	return FetchUserSecretsService{
		fetcher:   fetcher,
		decryptor: decryptor,
	}
}

func (srv FetchUserSecretsService) FetchUserSecrets(ctx context.Context, userID int) ([]byte, error) {
	secrets, err := srv.fetcher.ListUserSecrets(ctx, userID)
	if err != nil {
		return nil, err
	}
	var (
		credsSecrets      []models.Secret
		creditCardSecrets []models.Secret
		binDataSecrets    []models.Secret
	)
	for i := 0; i < len(secrets); i++ {
		switch secrets[i].SecretType {
		case models.CredentialsSecret:
			credsSecrets = append(credsSecrets, secrets[i])
		case models.CreditCardSecret:
			creditCardSecrets = append(creditCardSecrets, secrets[i])
		case models.BinDataSecret:
			binDataSecrets = append(binDataSecrets, secrets[i])
		}
	}

	archiveContent := bytes.Buffer{}
	zipWriter := zip.NewWriter(&archiveContent)
	err = srv.writeCredsSecrets(zipWriter, credsSecrets)
	if err != nil {
		return nil, err
	}
	err = srv.writeCreditCardsSecrets(zipWriter, creditCardSecrets)
	if err != nil {
		return nil, err
	}
	err = srv.writeBinDataSecrets(zipWriter, binDataSecrets)
	if err != nil {
		return nil, err
	}

	err = zipWriter.Close()
	if err != nil {
		return nil, err
	}

	return archiveContent.Bytes(), nil
}

func (srv FetchUserSecretsService) writeCredsSecrets(zipWriter *zip.Writer, credsSecrets []models.Secret) error {
	if len(credsSecrets) == 0 {
		return nil
	}

	creds := make([]*models.Credentials, len(credsSecrets))
	for i := 0; i < len(credsSecrets); i++ {
		decryptedCreds, err := srv.decryptor.Decrypt(
			credsSecrets[i].EncryptedData,
			credsSecrets[i].EncryptedKey,
		)
		if err != nil {
			return err
		}

		creds[i] = &models.Credentials{}
		err = creds[i].Unmarshall(decryptedCreds)
		if err != nil {
			return err
		}
		creds[i].ID = credsSecrets[i].ID
		creds[i].Description = credsSecrets[i].Description
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	f, err := zipWriter.Create("credentials.json")
	if err != nil {
		return err
	}

	_, err = f.Write(credsJSON)
	return err
}

func (srv FetchUserSecretsService) writeCreditCardsSecrets(
	zipWriter *zip.Writer,
	creditCardsSecrets []models.Secret) error {

	if len(creditCardsSecrets) == 0 {
		return nil
	}

	creditCards := make([]*models.CreditCard, len(creditCardsSecrets))
	for i := 0; i < len(creditCardsSecrets); i++ {
		decryptedCreditCard, err := srv.decryptor.Decrypt(
			creditCardsSecrets[i].EncryptedData,
			creditCardsSecrets[i].EncryptedKey,
		)
		if err != nil {
			return err
		}
		creditCards[i] = &models.CreditCard{}
		err = creditCards[i].Unmarshall(decryptedCreditCard)
		if err != nil {
			return err
		}
		creditCards[i].ID = creditCardsSecrets[i].ID
		creditCards[i].Description = creditCardsSecrets[i].Description
	}

	creditCardsJSON, err := json.Marshal(creditCards)
	if err != nil {
		return err
	}

	f, err := zipWriter.Create("credit_cards.json")
	if err != nil {
		return err
	}

	_, err = f.Write(creditCardsJSON)
	return err
}

func (srv FetchUserSecretsService) writeBinDataSecrets(
	zipWriter *zip.Writer,
	binDataSecrets []models.Secret) error {

	if len(binDataSecrets) == 0 {
		return nil
	}

	binData := make([]*models.BinData, len(binDataSecrets))
	for i := 0; i < len(binDataSecrets); i++ {
		decryptedBinData, err := srv.decryptor.Decrypt(
			binDataSecrets[i].EncryptedData,
			binDataSecrets[i].EncryptedKey,
		)
		if err != nil {
			return err
		}
		binData[i] = &models.BinData{}
		err = binData[i].Unmarshall(decryptedBinData)
		if err != nil {
			return err
		}

		var fname string
		if binData[i].Filename != "" {
			fname = binData[i].Filename
		} else {
			fname = "bin_data"
		}
		fname = fname + "_" + strconv.Itoa(binDataSecrets[i].ID)

		f, err := zipWriter.Create(fname)
		if err != nil {
			return err
		}
		_, err = f.Write(binData[i].Bytes)
		if err != nil {
			return err
		}
	}

	return nil
}
