package services_test

import (
	"errors"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type randGenMock struct{ mock.Mock }

func (m *randGenMock) Gen(size int) ([]byte, error) {
	args := m.Called(size)
	return args.Get(0).([]byte), args.Error(1)
}

func TestEncryptor(t *testing.T) {
	type want struct {
		encryptedData []byte
		encryptedKey  []byte
		errMsg        string
	}
	type randGenResult struct {
		res []byte
		err error
	}
	testCases := []struct {
		name          string
		msg           []byte
		rndGenResults []randGenResult
		want          want
	}{
		{
			name: "returns meta data about encrypted msg and encrypted msg",
			msg:  []byte("msg"),
			rndGenResults: []randGenResult{
				{res: []byte("abcdef0123456789")}, // key
				{res: []byte("0123456789ab")},     // iv for message
				{res: []byte("0123456789ab")},     // iv for key
			},
			want: want{
				encryptedData: []byte{
					48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 72, 118, 137, 134,
					31, 64, 1, 83, 226, 178, 51, 250, 128, 205, 219, 100, 204, 25, 242,
				},
				encryptedKey: []byte{
					48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 112, 199, 192, 232,
					36, 33, 177, 56, 14, 234, 249, 185, 124, 170, 254, 36, 93, 200, 29,
					74, 211, 111, 109, 123, 203, 28, 251, 175, 133, 94, 40, 132,
				},
			},
		},
		{
			name:          "returns error if could not generate key",
			rndGenResults: []randGenResult{{err: errors.New("error")}},
			want: want{
				errMsg: "error",
			},
		},
		{
			name: "returns error if could not generate nonce",
			rndGenResults: []randGenResult{
				{res: []byte("abcdef0123456789")},
				{err: errors.New("error")},
			},
			want: want{
				errMsg: "error",
			},
		},
	}

	rndGen := new(randGenMock)
	encryptor := services.NewDataEncryptor(rndGen)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, rndGenRes := range tc.rndGenResults {
				rndGen.On("Gen", mock.Anything).
					Return(rndGenRes.res, rndGenRes.err).
					Once()
			}

			encryptedData, encryptedKey, err := encryptor.Encrypt(tc.msg)
			if err == nil {
				assert.Equal(t, tc.want.encryptedData, encryptedData)
				assert.Equal(t, tc.want.encryptedKey, encryptedKey)
			} else {
				assert.EqualError(t, err, tc.want.errMsg)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	type want struct {
		msg    []byte
		errMsg string
	}
	testCases := []struct {
		name          string
		encryptedData []byte
		encryptedKey  []byte
		want          want
	}{
		{
			name: "returns decrypted msg",
			encryptedData: []byte{
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 72, 118, 137, 134,
				31, 64, 1, 83, 226, 178, 51, 250, 128, 205, 219, 100, 204, 25, 242,
			},
			encryptedKey: []byte{
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 112, 199, 192, 232,
				36, 33, 177, 56, 14, 234, 249, 185, 124, 170, 254, 36, 93, 200, 29,
				74, 211, 111, 109, 123, 203, 28, 251, 175, 133, 94, 40, 132,
			},
			want: want{
				msg: []byte("msg"),
			},
		},
	}

	rndGen := new(randGenMock)
	encryptor := services.NewDataEncryptor(rndGen)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := encryptor.Decrypt(tc.encryptedData, tc.encryptedKey)
			if err == nil {
				assert.Equal(t, tc.want.msg, msg)
			} else {
				assert.EqualError(t, err, tc.want.errMsg)
			}
		})
	}
}
