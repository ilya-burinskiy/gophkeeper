package services

import (
	"context"

	"github.com/ilya-burinskiy/gophkeeper/internal/models"
)

type SecretFinder interface {
	FindSecretByID(ctx context.Context, id int) (models.Secret, error)
}

type FindSecretService struct {
	finder SecretFinder
}

func NewFindSecretService(finder SecretFinder) FindSecretService {
	return FindSecretService{
		finder: finder,
	}
}

func (srv FindSecretService) Find(ctx context.Context, id int) (models.Secret, error) {
	return srv.finder.FindSecretByID(ctx, id)
}
