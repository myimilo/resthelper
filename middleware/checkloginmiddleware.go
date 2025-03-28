package middleware

import (
	"context"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/myimilo/resthelper/redistore"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckLoginMiddleware struct {
	SessionStore *redistore.RediStore
}

func NewCheckLoginMiddleware(store *redistore.RediStore) *CheckLoginMiddleware {
	return &CheckLoginMiddleware{
		SessionStore: store,
	}
}

// check login (from web) middleware
func (m *CheckLoginMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := m.SessionStore.Get(r, resthelper.SessionName)
		if err != nil {
			if cookieError, ok := err.(securecookie.MultiError); ok {
				if cookieError.IsDecode() {
					httpx.ErrorCtx(r.Context(), w, errorx.NewError(http.StatusUnauthorized))
					return
				}
				httpx.ErrorCtx(r.Context(), w, errorx.NewError(http.StatusInternalServerError))
				return
			}
			httpx.ErrorCtx(r.Context(), w, errorx.NewError(http.StatusInternalServerError))
			return
		}

		userId, find := session.Values["userId"]
		if !find || userId.(uint) <= 0 {
			httpx.ErrorCtx(r.Context(), w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeySession, session))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, userId.(uint)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyCodeId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyDeviceId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyPlatform, "web"))

		logx.Infof("event_check_login, platform: %v, userId: %v", "web", userId)

		next(w, r)
	}
}
