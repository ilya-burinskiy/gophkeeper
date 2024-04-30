package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type BinDataCreator interface {
	CreateBinData(ctx context.Context, filename string, filecontent []byte) error
	SetJWT(jwt string)
}

type CreateBinDataCmd struct {
	creator BinDataCreator
}

func NewCreateBinDataCmd(creator BinDataCreator) CreateBinDataCmd {
	return CreateBinDataCmd{
		creator: creator,
	}
}

func (createCmd CreateBinDataCmd) Execute(filePath, jwt string) error {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filePath, err)
	}
	createCmd.creator.SetJWT(jwt)
	return createCmd.creator.CreateBinData(
		context.TODO(),
		filepath.Base(filePath),
		fileContent,
	)
}
