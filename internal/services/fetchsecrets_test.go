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
		"504b03041400080008000000000000000000000000000000000010000000" +
			"63726564656e7469616c732e6a736f6e8aae5672492d4e2eca2c28c9cccf" +
			"53b25252d251f2c94fcf043173c0b48e5240627171797e518a9295524179" +
			"8a91526d2c200000ffff504b07084963f0653600000036000000504b0304" +
			"140008000800000000000000000000000000000000001100000063726564" +
			"69745f63617264732e6a736f6e8aae5672492d4e2eca2c28c9cccf53b252" +
			"52d251f22bcd4d4a2d52b25232343236363135353331864023632313907c" +
			"626e2a44a56b45416651a54b6209886f646064aa6b68a06b601462686a65" +
			"6060656010a5a4a3e41c166604525d1b0b080000ffff504b0708ed4129ca" +
			"630000006c000000504b0304140008000800000000000000000000000000" +
			"0000000003000000747874ca2d4ee702040000ffff504b0708b532d6740a" +
			"00000004000000504b01021400140008000800000000004963f065360000" +
			"003600000010000000000000000000000000000000000063726564656e74" +
			"69616c732e6a736f6e504b0102140014000800080000000000ed4129ca63" +
			"0000006c0000001100000000000000000000000000740000006372656469" +
			"745f63617264732e6a736f6e504b0102140014000800080000000000b532" +
			"d6740a000000040000000300000000000000000000000000160100007478" +
			"74504b05060000000003000300ae000000510100000000",
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
