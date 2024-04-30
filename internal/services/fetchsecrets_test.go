package services_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type secretFetcherMock struct{ mock.Mock }

func (m *secretFetcherMock) ListUserSecrets(ctx context.Context, userID int) ([]models.Secret, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]models.Secret), args.Error(1)
}

func TestFetchSecrets(t *testing.T) {
	type fetchResult struct {
		secrets []models.Secret
		err     error
	}
	type want struct {
		archiveContent []byte
		errMsg         string
	}

	encryptedCredentials, err := hex.DecodeString(
		"1f9de06b9cd6730bc56578be26824dc7ba2bd918013c05c8cf5887ed5c871" +
			"13a9400f7f9033cf1272cb276bf1907fe9b99449bcd6c05b4c21ad41c4fe3" +
			"0ef4366a6ba47f3c0710fe4cf0596dc810202896009eb6d2cde8a0df37bb095fce",
	)
	require.NoError(t, err)
	encryptedCreditCard, err := hex.DecodeString(
		"265ccc7c5fe005e24df26a447082f9a65410f55d59b66a995bdcae4fc756a" +
			"b0385a7f61ae1bef3cdc5cfeab9e918c2cd65e0dfbaa269f4f2a61dcd24c6" +
			"4eebd900b918e2f6122038ac80cd19b4edb04925043aaab1115072503bfaf" +
			"e69d09d0b559c0c9220c7f0ee3818210f4f70a31420472c2c32561ba9424e" +
			"256ebe2a4811e60028973c01571ced7033e07699eda34f33839309edc3fc4" +
			"a62b48a17d3fc3b0125076fa28da58b2d641cb3c56a",
	)
	require.NoError(t, err)
	encryptedBinData, err := hex.DecodeString(
		"3ef1a6a2190790fbd50887cbbea9ba23325d6b3f12757da8aab5402e0c042" +
			"02b9f68667f136773e5aa8aa3afa0ac0dba6d2ffbc252141aa09561da23ae" +
			"7d1d03bbf656fbc945568c2809484188de6b8ffdc058bc40ca7f80",
	)
	require.NoError(t, err)

	encryptedKey1, err := hex.DecodeString(
		"a45753d45593d5f4a9308df51213afb8f98732540d812cb579171acb70d8" +
			"51ec7ba2060eb123da78183bec53fa01da884a73bedf00adef4476e322e8",
	)
	require.NoError(t, err)
	encryptedKey2, err := hex.DecodeString(
		"710059167c3d76ffc4a4acaa8fd89b8a769418490ef335a43aa3c8af26cc" +
			"00fcf3423e0f68da0e5f17b224835d16be824f3eb4a2428ddf85afe2d784",
	)
	require.NoError(t, err)
	encryptedKey3, err := hex.DecodeString(
		"ee7bb9fdd3fef045def090816397596aef0387c5683240e7aaaba1a8b527" +
			"0bf7a39fa7442811addc51a357059cd4f24db9159f3b9b49bee642652ab7",
	)
	require.NoError(t, err)
	expctedArciveContent, err := hex.DecodeString(
		"504b030414000800080000000000000000000000000000000000100000006" +
			"3726564656e7469616c732e6a736f6e8aae56f27451b232d45172492d4e2ec" +
			"a2c28c9cccf53b25252d251f2c94fcf043173c0b48e5240627171797e518a9" +
			"2955241798a91526d2c200000ffff504b07082bb1120a3d0000003d0000005" +
			"04b03041400080008000000000000000000000000000000000011000000637" +
			"2656469745f63617264732e6a736f6e8aae56f27451b232d25172492d4e2ec" +
			"a2c28c9cccf53b25252d251f22bcd4d4a2d52b252323432363631353533318" +
			"64023632313907c626e2a44a56b45416651a54b6209886f646064aa6b68a06" +
			"b601462686a656060656010a5a4a3e41c166604525d1b0b080000ffff504b0" +
			"7081b646deb6a00000073000000504b0304140008000800000000000000000" +
			"00000000000000000050000007478745f33ca2d4ee702040000ffff504b070" +
			"8b532d6740a00000004000000504b01021400140008000800000000002bb11" +
			"20a3d0000003d0000001000000000000000000000000000000000006372656" +
			"4656e7469616c732e6a736f6e504b01021400140008000800000000001b646" +
			"deb6a0000007300000011000000000000000000000000007b0000006372656" +
			"469745f63617264732e6a736f6e504b0102140014000800080000000000b53" +
			"2d6740a0000000400000005000000000000000000000000002401000074787" +
			"45f33504b05060000000003000300b0000000610100000000",
	)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		userID   int
		fetchRes fetchResult
		want     want
	}{
		{
			name:   "returns archive with user secrets",
			userID: 1,
			fetchRes: fetchResult{
				secrets: []models.Secret{
					{
						ID:            1,
						UserID:        1,
						SecretType:    models.CredentialsSecret,
						EncryptedData: encryptedCredentials,
						EncryptedKey:  encryptedKey1,
					},
					{
						ID:            2,
						UserID:        1,
						SecretType:    models.CreditCardSecret,
						EncryptedData: encryptedCreditCard,
						EncryptedKey:  encryptedKey2,
					},
					{
						ID:            3,
						UserID:        1,
						SecretType:    models.BinDataSecret,
						EncryptedData: encryptedBinData,
						EncryptedKey:  encryptedKey3,
					},
				},
			},
			want: want{
				archiveContent: expctedArciveContent,
			},
		},
	}

	fetcher := new(secretFetcherMock)
	decryptor := services.NewDataEncryptor(services.CryptoRandGen{})
	fetchSrv := services.NewFetchUserSecretsService(fetcher, decryptor)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fetcherCall := fetcher.On("ListUserSecrets", mock.Anything, mock.Anything).
				Return(tc.fetchRes.secrets, tc.fetchRes.err)
			defer fetcherCall.Unset()

			archiveContent, err := fetchSrv.FetchUserSecrets(context.TODO(), tc.userID)
			if err == nil {
				fmt.Println(hex.EncodeToString(archiveContent))
				assert.Equal(t, tc.want.archiveContent, archiveContent)
			} else {
				assert.EqualError(t, err, tc.want.errMsg)
			}
		})
	}
}
