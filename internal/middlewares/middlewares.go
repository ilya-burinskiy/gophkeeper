package middlewares

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ilya-burinskiy/gophkeeper/internal/auth"
	"github.com/ilya-burinskiy/gophkeeper/internal/configs"
	"go.uber.org/zap"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	Status int
	Size   int
}

type contextKey string

const userIDKey contextKey = "user_id"

func (lw *loggingResponseWriter) Write(bytes []byte) (int, error) {
	size, err := lw.ResponseWriter.Write(bytes)
	lw.Size = size

	return size, err
}

func (lw *loggingResponseWriter) WriteHeader(status int) {
	lw.ResponseWriter.WriteHeader(status)
	lw.Status = status
}

func LogResponse(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lw := loggingResponseWriter{ResponseWriter: w}
			start := time.Now()
			h.ServeHTTP(&lw, r)
			duration := time.Since(start)
			logger.Info("response",
				zap.Int("status", lw.Status),
				zap.Duration("duration", duration),
				zap.Int("size", lw.Size),
			)
		})
	}
}

func LogRequest(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lw := loggingResponseWriter{ResponseWriter: w}
			h.ServeHTTP(&lw, r)
			logger.Info("got incoming http request",
				zap.String("method", r.Method),
				zap.String("uri", r.RequestURI),
			)
		})
	}
}

func Authenticate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims := &auth.Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(configs.SecretKey), nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserIDFromContext(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(userIDKey).(int)
	return userID, ok
}
