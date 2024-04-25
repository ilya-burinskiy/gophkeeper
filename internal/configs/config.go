package configs

import (
	"os"
	"time"
)

const AuthTokenExp = 24 * time.Hour
const SecretKey = "secret"

type Config struct {
	RunAddr       string
	DSN           string
	ServerCRTPath string
	ServerKeyPath string
}

func Parse() Config {
	config := Config{
		RunAddr: "localhost:8000",
		DSN:     "postgres://gophkeeper:password@localhost:5432/gophkeeper",
	}

	if envRunAdd := os.Getenv("RUN_ADDRESS"); envRunAdd != "" {
		config.RunAddr = envRunAdd
	}
	if envDSN := os.Getenv("DATABASE_URI"); envDSN != "" {
		config.DSN = envDSN
	}
	config.ServerCRTPath = os.Getenv("SERVER_CRT_PATH")
	config.ServerKeyPath = os.Getenv("SERVER_KEY_PATH")

	return config
}
