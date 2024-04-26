package main

import (
	"crypto/tls"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ilya-burinskiy/gophkeeper/internal/configs"
	"github.com/ilya-burinskiy/gophkeeper/internal/handlers"
	"github.com/ilya-burinskiy/gophkeeper/internal/middlewares"
	"github.com/ilya-burinskiy/gophkeeper/internal/services"
	"github.com/ilya-burinskiy/gophkeeper/internal/storage"
	"go.uber.org/zap"
)

func main() {
	config := configs.Parse()
	store, err := storage.NewDBStorage(config.DSN)
	if err != nil {
		panic(err)
	}
	logger := configureLogger("info")
	router := chi.NewRouter()
	router.Use(
		middlewares.LogResponse(logger),
		middlewares.LogRequest(logger),
	)

	registerSrv := services.NewRegisterService(store)
	authSrv := services.NewAuthenticateService(store)
	encryptor := services.NewDataEncryptor(services.CryptoRandGen{})
	createSecretSrv := services.NewCreateSecretService(store, encryptor)
	findSrv := services.NewFindSecretService(store)
	updateSrv := services.NewUpdateSecretService(store, encryptor)
	fetchSrv := services.NewFetchUserSecretsService(store, encryptor)
	deleteSrv := services.NewDeleteSecretService(store)

	configureUserRouter(logger, registerSrv, authSrv, router)
	configureSecretRouter(
		logger,
		createSecretSrv,
		findSrv,
		updateSrv,
		fetchSrv,
		deleteSrv,
		router,
	)

	cert, err := tls.LoadX509KeyPair(config.ServerCRTPath, config.ServerKeyPath)
	if err != nil {
		panic(err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server := http.Server{
		Handler:   router,
		Addr:      config.RunAddr,
		TLSConfig: tlsConfig,
	}
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

func configureUserRouter(
	logger *zap.Logger,
	registerSrv services.RegisterService,
	authSrv services.AuthenticateService,
	mainRouter chi.Router) {

	handler := handlers.NewUserHandlers(logger)
	mainRouter.Group(func(router chi.Router) {
		router.Use(middleware.AllowContentType("application/json"))
		router.Post("/api/user/register", handler.Register(registerSrv))
		router.Post("/api/user/login", handler.Authenticate(authSrv))
	})
}

func configureSecretRouter(
	logger *zap.Logger,
	createSrv services.CreateSecretService,
	findSrv services.FindSecretService,
	updateSrv services.UpdateSecretService,
	fetchSrv services.FetchUserSecretsService,
	deleteSrv services.DeleteSecretService,
	mainRouter chi.Router) {

	handler := handlers.NewSecretHandler(logger)
	mainRouter.Group(func(router chi.Router) {
		router.Use(middlewares.Authenticate)
		router.Post("/api/secrets", handler.Create(createSrv))
		router.Patch("/api/secrets/{id}", handler.Update(findSrv, updateSrv))
		router.Get("/api/secrets", handler.GetUserSecrets(fetchSrv))
		router.Delete("/api/secrets/{id}", handler.Delete(findSrv, deleteSrv))
	})
}

func configureLogger(level string) *zap.Logger {
	logLvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		panic(err)
	}
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level = logLvl
	logger, err := loggerConfig.Build()
	if err != nil {
		panic(err)
	}

	return logger
}
