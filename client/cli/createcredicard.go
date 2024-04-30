package cli

import "context"

type CreditCardCreator interface {
	CreateCreditCard(ctx context.Context, number, name, expiryDateStr, cvv2 string) error
	SetJWT(jwtStr string)
}

type CreateCreditCardCmd struct {
	creator CreditCardCreator
}

func NewCreateCreditCardCmd(creator CreditCardCreator) CreateCreditCardCmd {
	return CreateCreditCardCmd{
		creator: creator,
	}
}

func (createCmd CreateCreditCardCmd) Execute(number, name, expiryDateStr, cvv2, jwtStr string) error {
	createCmd.creator.SetJWT(jwtStr)
	return createCmd.creator.CreateCreditCard(
		context.TODO(),
		number,
		name,
		expiryDateStr,
		cvv2,
	)
}
