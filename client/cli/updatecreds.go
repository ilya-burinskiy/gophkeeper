package cli

import "context"

type CredentialsUpdater interface {
	UpdateCredentials(ctx context.Context, id int64, login, password string) error
	SetJWT(jwt string)
}

type UpdateCredentialsCmd struct {
	updater CredentialsUpdater
}

func NewUpdateCredentialsCmd(updater CredentialsUpdater) UpdateCredentialsCmd {
	return UpdateCredentialsCmd{
		updater: updater,
	}
}

func (updateCmd UpdateCredentialsCmd) Execute(id int64, login, password, jwtStr string) error {
	updateCmd.updater.SetJWT(jwtStr)
	return updateCmd.updater.UpdateCredentials(
		context.TODO(),
		id,
		login,
		password,
	)
}
