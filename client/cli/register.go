package cli

import (
	"context"
	"errors"
)

type UserRegistrator interface {
	RegisterUser(ctx context.Context, login, password string) error
}

type RegisterCmd struct {
	usrReg UserRegistrator
}

func NewRegisterCmd(usrReg UserRegistrator) RegisterCmd {
	return RegisterCmd{
		usrReg: usrReg,
	}
}

func (regCmd RegisterCmd) Execute(login, password string) error {
	if login == "" {
		return errors.New("login must be non empty")
	}
	if password == "" {
		return errors.New("password must be non empty")
	}

	return regCmd.usrReg.RegisterUser(context.TODO(), login, password)
}
