package cli

import "context"

type CreditCardUpdater interface {
	UpdateCreditCard(ctx context.Context, id int64, number, name, expiryDate, cvv2 string) error
	SetJWT(jwt string)
}

type UpdateCreditCardCmd struct {
	updater CreditCardUpdater
}

func NewUpdateCreditCardCmd(updater CreditCardUpdater) UpdateCreditCardCmd {
	return UpdateCreditCardCmd{
		updater: updater,
	}
}

func (updCmd UpdateCreditCardCmd) Execute(
	id int64,
	number,
	name,
	expiryDate,
	cvv2,
	jwt string) error {

	updCmd.updater.SetJWT(jwt)
	return updCmd.updater.UpdateCreditCard(
		context.TODO(),
		id,
		number,
		name,
		expiryDate,
		cvv2,
	)
}
