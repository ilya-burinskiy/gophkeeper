package cli

import "context"

type SecretDeleter interface {
	DeleteSecret(ctx context.Context, id int64) error
	SetJWT(jwt string)
}

type DeleteSecretCmd struct {
	deleter SecretDeleter
}

func NewDeleteSecretCmd(deleter SecretDeleter) DeleteSecretCmd {
	return DeleteSecretCmd{
		deleter: deleter,
	}
}

func (delCmd DeleteSecretCmd) Execute(id int64, jwt string) error {
	delCmd.deleter.SetJWT(jwt)
	return delCmd.deleter.DeleteSecret(
		context.TODO(),
		id,
	)
}
