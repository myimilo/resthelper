package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/securecookie"
	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/myimilo/resthelper/redistore"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckUserMiddleware struct {
	SessionStore *redistore.RediStore
	redis        *redis.Redis
	AccessSecret string
	superKey     string
}

func NewCheckUserMiddleware(redis *redis.Redis, accessSecret string, superKey string, store *redistore.RediStore) *CheckUserMiddleware {
	return &CheckUserMiddleware{
		redis:        redis,
		AccessSecret: accessSecret,
		SessionStore: store,
		superKey:     superKey,
	}
}

// check login (from app or web) middleware
func (m *CheckUserMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Try to authenticate app user
		var err error
		if err = m.checkAppUser(r); err == nil {
			logx.Infof("check app user success, platform: %v, userId: %v, codeId: %v, deviceId: %v", "app",
				r.Context().Value(resthelper.ContextKeyUserId),
				r.Context().Value(resthelper.ContextKeyCodeId),
				r.Context().Value(resthelper.ContextKeyDeviceId),
			)
			next(w, r)
			return
		}
		logx.Errorf("check app user failed, error: %v, try to check web user", err)

		// Try to authenticate web user
		if err = m.checkWebUser(r); err == nil {
			logx.Infof("check web user success, platform: %v, userId: %v", "web", r.Context().Value(resthelper.ContextKeyUserId))
			next(w, r)
			return
		}
		logx.Errorf("check web user failed, error: %v, try to check super user", err)

		// Try to authenticate super user
		if err = m.checkSuperUser(r); err == nil {
			logx.Infof("check super user success, platform: %v, userId: %v, codeId: %v, deviceId: %v", "super",
				r.Context().Value(resthelper.ContextKeyUserId),
				r.Context().Value(resthelper.ContextKeyCodeId),
				r.Context().Value(resthelper.ContextKeyDeviceId),
			)
			next(w, r)
			return
		}
		logx.Errorf("check super user failed, error: %v", err)

		// If all authentication methods fail, return unauthorized
		httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
	}
}

func (m *CheckUserMiddleware) checkSuperUser(r *http.Request) error {
	if m.superKey == "" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	superKey := r.Header.Get("Authorization")
	if superKey == "" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	fields := strings.Fields(superKey)
	if len(fields) != 2 || strings.ToLower(fields[0]) != "bearer" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	superKey = fields[1]
	if superKey != m.superKey {
		return errorx.NewError(http.StatusUnauthorized)
	}

	var userId, codeId, deviceId uint64

	userIdStr := r.Header.Get("X-User-Id")
	if userIdStr != "" {
		userId, _ = strconv.ParseUint(userIdStr, 10, 64)
	}

	codeIdStr := r.Header.Get("X-Code-Id")
	if codeIdStr != "" {
		codeId, _ = strconv.ParseUint(codeIdStr, 10, 64)
	}

	deviceIdStr := r.Header.Get("X-Device-Id")
	if deviceIdStr != "" {
		deviceId, _ = strconv.ParseUint(deviceIdStr, 10, 64)
	}

	// Create a new context with all values and update the request once
	ctx := r.Context()
	ctx = context.WithValue(ctx, resthelper.ContextKeyUserId, uint(userId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyCodeId, uint(codeId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyDeviceId, uint(deviceId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyPlatform, "super")
	*r = *r.WithContext(ctx)

	return nil
}

func (m *CheckUserMiddleware) checkWebUser(r *http.Request) error {
	session, err := m.SessionStore.Get(r, resthelper.SessionName)
	if err != nil {
		if cookieError, ok := err.(securecookie.MultiError); ok {
			if cookieError.IsDecode() {
				return errorx.NewError(http.StatusUnauthorized)
			}
			return errorx.NewError(http.StatusInternalServerError)
		}
		return errorx.NewError(http.StatusInternalServerError)
	}

	userId, find := session.Values["userId"]
	if !find || userId.(uint) <= 0 {
		return errorx.NewError(http.StatusUnauthorized)
	}

	// Create a new context with all values and update the request once
	ctx := r.Context()
	ctx = context.WithValue(ctx, resthelper.ContextKeySession, session)
	ctx = context.WithValue(ctx, resthelper.ContextKeyUserId, userId.(uint))
	ctx = context.WithValue(ctx, resthelper.ContextKeyCodeId, uint(0))
	ctx = context.WithValue(ctx, resthelper.ContextKeyDeviceId, uint(0))
	ctx = context.WithValue(ctx, resthelper.ContextKeyPlatform, "web")
	*r = *r.WithContext(ctx)

	return nil
}

func (m *CheckUserMiddleware) checkAppUser(r *http.Request) error {
	accessToken := r.Header.Get("Authorization")
	if accessToken == "" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	fields := strings.Fields(accessToken)
	if len(fields) != 2 || strings.ToLower(fields[0]) != "bearer" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	accessToken = fields[1]

	if v, err := m.redis.Get(fmt.Sprintf(AccessTokenPrefix, accessToken)); err != nil || v == "" {
		return errorx.NewError(http.StatusUnauthorized)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.AccessSecret), nil
	})
	if err != nil || !token.Valid {
		return errorx.NewError(http.StatusUnauthorized)
	}

	var strCodeId, strUserId, strDeviceId string
	strCodeId, ok := claims["codeId"].(string)
	if !ok {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse code ID"))
	}
	strUserId, ok = claims["userId"].(string)
	if !ok {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse user ID"))
	}
	strDeviceId, ok = claims["deviceId"].(string)
	if !ok {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse device ID"))
	}

	codeId, err := strconv.ParseUint(strCodeId, 10, 64)
	if err != nil {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse code ID"))
	}

	userId, err := strconv.ParseUint(strUserId, 10, 64)
	if err != nil {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse user ID"))
	}

	deviceId, err := strconv.ParseUint(strDeviceId, 10, 64)
	if err != nil {
		return errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse device ID"))
	}

	// Create a new context with all values and update the request once
	ctx := r.Context()
	ctx = context.WithValue(ctx, resthelper.ContextKeyUserId, uint(userId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyCodeId, uint(codeId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyDeviceId, uint(deviceId))
	ctx = context.WithValue(ctx, resthelper.ContextKeyPlatform, "app")
	*r = *r.WithContext(ctx)

	return nil
}
