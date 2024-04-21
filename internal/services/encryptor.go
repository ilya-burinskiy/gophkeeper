package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

var masterKey = [32]byte{
	239, 140, 200, 100, 31, 6, 108, 25, 158, 54, 149, 16, 138, 90, 157, 144,
	53, 144, 0, 193, 140, 107, 205, 41, 70, 167, 116, 218, 39, 58, 207, 240,
}

type RandGen interface {
	Gen(size int) ([]byte, error)
}

type CryptoRandGen struct{}

func (cr CryptoRandGen) Gen(size int) ([]byte, error) {
	res := make([]byte, size)
	_, err := rand.Read(res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type DataEncryptor struct {
	randGen RandGen
}

func NewDataEncryptor(randGen RandGen) DataEncryptor {
	return DataEncryptor{
		randGen: randGen,
	}
}

func (de DataEncryptor) Encrypt(msg []byte) ([]byte, []byte, error) {
	key, err := de.randGen.Gen(len(masterKey))
	if err != nil {
		return nil, nil, err
	}
	encodedMsg, err := de.encrypt(msg, key)
	if err != nil {
		return nil, nil, err
	}
	encodedKey, err := de.encrypt(key, masterKey[:])
	if err != nil {
		return nil, nil, err
	}

	return encodedMsg, encodedKey, nil
}

func (de DataEncryptor) ReEncrypt(msg []byte, encryptedKey []byte) ([]byte, error) {
	key, err := de.decrypt(encryptedKey, masterKey[:])
	if err != nil {
		return nil, err
	}
	return de.encrypt(msg, key)
}

func (de DataEncryptor) Decrypt(ciphertext []byte, encryptedKey []byte) ([]byte, error) {
	decryptedKey, err := de.decrypt(encryptedKey, masterKey[:])
	if err != nil {
		return nil, err
	}
	msg, err := de.decrypt(ciphertext, decryptedKey)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (de DataEncryptor) encrypt(msg []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, gcm.NonceSize())
	iv := ciphertext[:gcm.NonceSize()]
	randBytes, err := de.randGen.Gen(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	copy(iv, randBytes)
	ciphertext = gcm.Seal(ciphertext, iv, msg, nil)

	return ciphertext, nil
}

func (de DataEncryptor) decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	msg, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return msg, nil
}
