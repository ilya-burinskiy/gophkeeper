package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type BinDataUpdater interface {
	UpdateBinData(ctx context.Context, id int64, filename string, fileContent []byte) error
	SetJWT(jwt string)
}

type UpdateBinDataCmd struct {
	updater BinDataUpdater
}

func NewUpdateBinDataCmd(updater BinDataUpdater) UpdateBinDataCmd {
	return UpdateBinDataCmd{
		updater: updater,
	}
}

func (updCmd UpdateBinDataCmd) Execute(id int64, filePath, jwt string) error {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", filePath, err)
	}
	updCmd.updater.SetJWT(jwt)
	return updCmd.updater.UpdateBinData(
		context.TODO(),
		id,
		filepath.Base(filePath),
		fileContent,
	)
}
