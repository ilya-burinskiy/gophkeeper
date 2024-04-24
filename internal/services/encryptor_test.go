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

func TestReEncrypt(t *testing.T) {
	type randGenResult struct {
		res []byte
		err error
	}
	type want struct {
		encryptedMsg []byte
		errMsg       string
	}
	testCases := []struct {
		name         string
		msg          []byte
		encryptedKey []byte
		randGenRes   randGenResult
		want         want
	}{
		{
			name: "reencrypts message",
			msg:  []byte("new msg"),
			encryptedKey: []byte{
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 112, 199, 192, 232,
				36, 33, 177, 56, 14, 234, 249, 185, 124, 170, 254, 36, 93, 200, 29,
				74, 211, 111, 109, 123, 203, 28, 251, 175, 133, 94, 40, 132,
			},
			randGenRes: randGenResult{
				res: []byte("abcdef0123456789"),
			},
			want: want{
				encryptedMsg: []byte{
					0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
					0x39, 0x1c, 0x99, 0x5b, 0x74, 0x70, 0x41, 0xa9, 0x8d, 0xa2, 0xb3, 0x69,
					0x70, 0xc5, 0x60, 0x40, 0xfb, 0x4f, 0x8, 0x32, 0x38, 0xe7, 0x16,
				},
			},
		},
	}

	rndGen := new(randGenMock)
	encryptor := services.NewDataEncryptor(rndGen)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rndGen.On("Gen", mock.Anything).
				Return(tc.randGenRes.res, tc.randGenRes.err).
				Once()
			reEncryptedMsg, err := encryptor.ReEncrypt(tc.msg, tc.encryptedKey)
			if err == nil {
				assert.Equal(t, tc.want.encryptedMsg, reEncryptedMsg)
			} else {
				assert.EqualError(t, err, tc.want.errMsg)
			}
		})
	}
}
