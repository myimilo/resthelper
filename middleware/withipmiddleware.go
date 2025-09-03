package middleware

import (
	"context"
	"net/http"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/utils"
)

type WithIPMiddleware struct {
}

func NewWithIPMiddleware() *WithIPMiddleware {
	return &WithIPMiddleware{}
}

func (m *WithIPMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := utils.GetIP(r)
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyIP, ip))
		next(w, r)
	}
}
