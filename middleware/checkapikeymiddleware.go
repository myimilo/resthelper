package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckApiKeyMiddleware struct {
	ApiKey string
}

func NewCheckApiKeyMiddleware(apiKey string) *CheckApiKeyMiddleware {
	return &CheckApiKeyMiddleware{ApiKey: apiKey}
}

func (m *CheckApiKeyMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := extractApiKey(r)
		if apiKey == "" || apiKey != m.ApiKey {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyCodeId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyDeviceId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyPlatform, "api"))

		// Passthrough to next handler if need
		next(w, r)
	}
}

func extractApiKey(r *http.Request) string {
	// Try X-API-Key header first
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Try Authorization header with Bearer format
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		fields := strings.Fields(authHeader)
		if len(fields) == 2 && strings.ToLower(fields[0]) == "bearer" {
			return fields[1]
		}
	}

	return ""
}
