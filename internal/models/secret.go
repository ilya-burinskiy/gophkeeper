package models

type SecretType int

const (
	_ SecretType = iota
	CredentialsSecret
	CreditCardSecret
	BinDataSecret
)

type Secret struct {
	ID            int
	UserID        int
	SecretType    SecretType
	Description   string
	EncryptedData []byte
	EncryptedKey  []byte
}
