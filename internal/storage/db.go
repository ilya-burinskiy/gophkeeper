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

func (db *DBStorage) FindUserByLogin(ctx context.Context, login string) (models.User, error) {
	row := db.pool.QueryRow(
		ctx,
		`SELECT "id", "encrypted_password"
		 FROM "users"
		 WHERE "login" = @login`,
		pgx.NamedArgs{"login": login},
	)
	user := models.User{Login: login}
	var id int
	var encryptedPassword []byte
	err := row.Scan(&id, &encryptedPassword)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user, ErrUserNotFound{User: user}
		}
		return user, fmt.Errorf("failed to find user: %w", err)
	}

	user.ID = id
	user.EncryptedPassword = encryptedPassword

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

func (db *DBStorage) FindSecretByID(ctx context.Context, id int) (models.Secret, error) {
	row := db.pool.QueryRow(
		ctx,
		`SELECT "user_id", "type", "description", "encrypted_data", "encrypted_key"
		 FROM "secrets"
		 WHERE "id" = $1`,
		id,
	)
	secret := models.Secret{ID: id}
	err := row.Scan(
		&secret.UserID,
		&secret.SecretType,
		&secret.Description,
		&secret.EncryptedData,
		&secret.EncryptedKey,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return secret, ErrSecretNotFound{Secret: secret}
		}
		return secret, fmt.Errorf("failed to find secret: %w", err)
	}

	return secret, nil
}

func (db *DBStorage) UpdateSecret(
	ctx context.Context,
	secretID int,
	description string,
	newData []byte) error {

	_, err := db.pool.Exec(
		ctx,
		`UPDATE "secrets" SET "encrypted_data" = $1, "description" = $2 WHERE "id" = $3`,
		newData, description, secretID,
	)
	if err != nil {
		return fmt.Errorf("failed to update encypted data: %w", err)
	}

	return nil
}

func (db *DBStorage) ListUserSecrets(ctx context.Context, userID int) ([]models.Secret, error) {
	rows, err := db.pool.Query(
		ctx,
		`SELECT "id", "type", "description", "encrypted_data", "encrypted_key"
		 FROM "secrets" WHERE "user_id" = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user secrets: %w", err)
	}

	result, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (models.Secret, error) {
		var secret models.Secret
		err := row.Scan(
			&secret.ID,
			&secret.SecretType,
			&secret.Description,
			&secret.EncryptedData,
			&secret.EncryptedKey,
		)
		return secret, err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user secrets: %w", err)
	}

	return result, nil
}

func (db *DBStorage) DeleteSecret(ctx context.Context, secretID int) error {
	_, err := db.pool.Exec(
		ctx,
		`DELETE FROM "secrets" WHERE "id" = $1`,
		secretID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete secret with id=%d", secretID)
	}

	return nil
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
