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
	default:
		log.Fatal("invalid command")
	}
}
