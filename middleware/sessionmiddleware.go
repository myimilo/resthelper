package middleware

import (
	"context"
	"net/http"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/redistore"
	"github.com/zeromicro/go-zero/core/logx"
)

type SessionMiddleware struct {
	SessionStore *redistore.RediStore
}

func NewSessionMiddleware(store *redistore.RediStore) *SessionMiddleware {
	return &SessionMiddleware{
		SessionStore: store,
	}
}

func (m *SessionMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if session, err := m.SessionStore.Get(r, resthelper.SessionName); err != nil {
			logx.Error(err)
		} else {
			r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeySession, session))
			if uid, find := session.Values["userId"]; find && uid.(uint) > 0 {
				r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, uid.(uint)))
				logx.Infof("event_active_session, userid: %v", uid)
			} else {
				r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, uint(0)))
				logx.Info("event_active_session, userid: 0")
			}
			if role, find := session.Values["role"]; find && role.(string) != "" {
				r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserRole, role.(string)))
			} else {
				r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserRole, resthelper.RoleUser))
			}
			r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyCodeId, uint(0)))
			r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyDeviceId, uint(0)))
			r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyPlatform, "web"))
		}
		next(w, r)
	}
}
