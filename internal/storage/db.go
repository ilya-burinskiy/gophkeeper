package storage

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DBStorage struct {
	pool *pgxpool.Pool
}

func NewDBStorage(dsn string) (*DBStorage, error) {
	if err := runMigrations(dsn); err != nil {
		return nil, fmt.Errorf("failed to run DB migrations: %w", err)
	}

	pool, err := pgxpool.New(context.TODO(), dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create a connection pool: %w", err)
	}

	return &DBStorage{
		pool: pool,
	}, nil
}

func (db *DBStorage) CreateUser(ctx context.Context, login string, encryptedPassword []byte) (models.User, error) {
	row := db.pool.QueryRow(
		ctx,
		`INSERT INTO "users" ("login", "encrypted_password") VALUES (@login, @encryptedPassword) RETURNING "id"`,
		pgx.NamedArgs{"login": login, "encryptedPassword": encryptedPassword},
	)
	var userID int
	user := models.User{Login: login, EncryptedPassword: encryptedPassword}
	err := row.Scan(&userID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return user, ErrUserNotUniq{User: user}
		}
		return user, fmt.Errorf("failed to create user %w", err)
	}
	user.ID = userID

	return user, nil
}

func (db *DBStorage) CreateSecret(
	ctx context.Context,
	userID int,
	secretType models.SecretType,
	description string,
	encryptedData []byte,
	encryptedKey []byte) (models.Secret, error) {

	row := db.pool.QueryRow(
		ctx,
		`INSERT INTO "secrets" ("user_id", "type", "description", "encrypted_data", "encrypted_key")
		 VALUES (@userID, @secretType, @description, @encryptedData, @encryptedKey) RETURNING "id"`,
		pgx.NamedArgs{
			"userID":        userID,
			"secretType":    secretType,
			"description":   description,
			"encryptedData": encryptedData,
			"encryptedKey":  encryptedKey,
		},
	)
	var secretID int
	secret := models.Secret{
		UserID:        userID,
		SecretType:    secretType,
		Description:   description,
		EncryptedData: encryptedData,
		EncryptedKey:  encryptedKey,
	}
	if err := row.Scan(&secretID); err != nil {
		return secret, fmt.Errorf("failed to create secret: %w", err)
	}
	secret.ID = secretID

	return secret, nil
}

//go:embed db/migrations/*.sql
var migrationsDir embed.FS

func runMigrations(dsn string) error {
	d, err := iofs.New(migrationsDir, "db/migrations")
	if err != nil {
		return fmt.Errorf("failed to return an iofs driver: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", d, dsn)
	if err != nil {
		return fmt.Errorf("failed to get a new migrate instance: %w", err)
	}

	if err := m.Up(); err != nil {
		if !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	}

	return nil
}
