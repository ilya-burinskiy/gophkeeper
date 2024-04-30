package cli

import "context"

type CredentialsCreator interface {
	CreateCredentials(ctx context.Context, login, password string) error
	SetJWT(jwt string)
}

type CreateCredentialsCmd struct {
	creator CredentialsCreator
}

func NewCreateCredentialsCmd(creator CredentialsCreator) CreateCredentialsCmd {
	return CreateCredentialsCmd{
		creator: creator,
	}
}

func (createCmd CreateCredentialsCmd) Execute(login, password, jwtStr string) error {
	createCmd.creator.SetJWT(jwtStr)
	return createCmd.creator.CreateCredentials(
		context.TODO(),
		login,
		password,
	)
}
