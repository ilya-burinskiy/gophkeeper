package cli

import "context"

type UserAuthenticator interface {
	AuthenticateUser(ctx context.Context, login, password string) (string, error)
}

type AuthenticateCmd struct {
	usrAuth UserAuthenticator
}

func NewAuthenticateCmd(usrAuth UserAuthenticator) AuthenticateCmd {
	return AuthenticateCmd{
		usrAuth: usrAuth,
	}
}

func (authCmd AuthenticateCmd) Execute(login, password string) (string, error) {
	return authCmd.usrAuth.AuthenticateUser(
		context.TODO(),
		login,
		password,
	)
}
