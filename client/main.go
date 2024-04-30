package main

import (
	"flag"
	"log"
	"os"

	"github.com/ilya-burinskiy/gophkeeper/client/api"
	"github.com/ilya-burinskiy/gophkeeper/client/cli"
)

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("please specify command")
	}

	cmd, args := args[0], args[1:]
	client := api.NewGophkeeperClient(os.Getenv("BASE_URL"))
	switch cmd {
	case "register":
		execRegisterCmd(args, client)
	case "authenticate":
		execAuthenticateCmd(args, client)
	case "get-secrets":
		execGetSecretsCmd(args, client)
	case "create-creds":
		execCreateCredsCmd(args, client)
	case "create-credit-card":
		execCreateCreditCardCmd(args, client)
	case "create-bin-data":
		execCreateBinDataCmd(args, client)
	case "update-creds":
		execUpdateCredsCmd(args, client)
	case "update-credit-card":
		execUpdateCreditCardCmd(args, client)
	default:
		log.Fatal("invalid command")
	}
}

func execRegisterCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("register", flag.ExitOnError)
	var login, password string
	flagSet.StringVar(&login, "login", "", "your login")
	flagSet.StringVar(&password, "password", "", "your password")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse register flags", err)
	}

	regCmd := cli.NewRegisterCmd(client)
	err = regCmd.Execute(login, password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execAuthenticateCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("authenticate", flag.ExitOnError)
	var login, password string
	flagSet.StringVar(&login, "login", "", "your login")
	flagSet.StringVar(&password, "password", "", "your password")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse authenticate flags", err)
	}

	authCmd := cli.NewAuthenticateCmd(client)
	jwtStr, err := authCmd.Execute(login, password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("jwt=", jwtStr)
}

func execGetSecretsCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("get-secrets", flag.ExitOnError)
	var outputFname, jwt string
	flagSet.StringVar(&outputFname, "output", "archive.zip", "output filename")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse get-secrets flags", err)
	}

	getCmd := cli.NewGetSecretCmd(client)
	err = getCmd.Execute(outputFname, jwt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execCreateCredsCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("create-creds", flag.ExitOnError)
	var login, password, jwt string
	flagSet.StringVar(&login, "login", "", "login")
	flagSet.StringVar(&password, "password", "", "password")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse get-secrets flags", err)
	}

	createCmd := cli.NewCreateCredentialsCmd(client)
	err = createCmd.Execute(login, password, jwt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execCreateCreditCardCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("create-credit-card", flag.ExitOnError)
	var number, name, expiryDate, cvv2, jwt string
	flagSet.StringVar(&number, "number", "", "credit card number")
	flagSet.StringVar(&name, "name", "", "credit card owner number")
	flagSet.StringVar(&expiryDate, "date", "", "credit card expriry date in RFC3339 format")
	flagSet.StringVar(&cvv2, "cvv2", "", "credit card CVV2")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse create-credit-card flags", err)
	}

	createCmd := cli.NewCreateCreditCardCmd(client)
	err = createCmd.Execute(number, name, expiryDate, cvv2, jwt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execCreateBinDataCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("create-bin-data", flag.ExitOnError)
	var filepath, jwt string
	flagSet.StringVar(&filepath, "path", "", "file path")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	if err := flagSet.Parse(args); err != nil {
		log.Fatal("failed to parse create-bin-data flags", err)
	}

	createCmd := cli.NewCreateBinDataCmd(client)
	if err := createCmd.Execute(filepath, jwt); err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execUpdateCredsCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("update-creds", flag.ExitOnError)
	var id int64
	var login, password, jwt string
	flagSet.Int64Var(&id, "id", 0, "credentials ID")
	flagSet.StringVar(&login, "login", "", "login")
	flagSet.StringVar(&password, "password", "", "password")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse update-creds flags", err)
	}

	updateCmd := cli.NewUpdateCredentialsCmd(client)
	err = updateCmd.Execute(id, login, password, jwt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}

func execUpdateCreditCardCmd(args []string, client *api.GophkeeperClient) {
	flagSet := flag.NewFlagSet("update-credit-card", flag.ExitOnError)
	var id int64
	var number, name, expiryDate, cvv2, jwt string
	flagSet.Int64Var(&id, "id", 0, "credit card ID")
	flagSet.StringVar(&number, "number", "", "credit card number")
	flagSet.StringVar(&name, "name", "", "credit card owner number")
	flagSet.StringVar(&expiryDate, "date", "", "credit card expriry date in RFC3339 format")
	flagSet.StringVar(&cvv2, "cvv2", "", "credit card CVV2")
	flagSet.StringVar(&jwt, "jwt", "", "authentication JWT")
	err := flagSet.Parse(args)
	if err != nil {
		log.Fatal("failed to parse update-credit-card flags", err)
	}

	updateCmd := cli.NewUpdateCreditCardCmd(client)
	err = updateCmd.Execute(id, number, name, expiryDate, cvv2, jwt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Success")
}
