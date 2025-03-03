package middleware

import (
	"net/http"

	"github.com/gorilla/csrf"
	_ "github.com/zeromicro/go-zero/core/logx"
)

type CSRFMiddleware struct {
	SessionAuthKey string
}

func NewCSRFMiddleware(auth_key string) *CSRFMiddleware {
	return &CSRFMiddleware{auth_key}
}

func (m *CSRFMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrf.Protect([]byte(m.SessionAuthKey))(next).ServeHTTP(w, r)
	}
}
