package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest/httpx"
)

const AccessTokenPrefix = "access_token::%s"

type CheckTokenMiddleware struct {
	redis        *redis.Redis
	AccessSecret string
}

func NewCheckTokenMiddleware(redis *redis.Redis, accessSecret string) *CheckTokenMiddleware {
	return &CheckTokenMiddleware{
		redis:        redis,
		AccessSecret: accessSecret,
	}
}

// check login (from app) middleware
func (m *CheckTokenMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Header.Get("Authorization")
		if accessToken == "" {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		fields := strings.Fields(accessToken)
		if len(fields) != 2 || strings.ToLower(fields[0]) != "bearer" {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		accessToken = fields[1]

		if v, err := m.redis.Get(fmt.Sprintf(AccessTokenPrefix, accessToken)); err != nil || v == "" {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(accessToken, &claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(m.AccessSecret), nil
		})
		if err != nil || !token.Valid {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		var strCodeId, strUserId, strDeviceId string
		strCodeId, ok := claims["codeId"].(string)
		if !ok {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse code ID")))
			return
		}
		strUserId, ok = claims["userId"].(string)
		if !ok {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse user ID")))
			return
		}
		strDeviceId, ok = claims["deviceId"].(string)
		if !ok {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse device ID")))
			return
		}

		codeId, err := strconv.ParseUint(strCodeId, 10, 64)
		if err != nil {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse code ID")))
			return
		}

		userId, err := strconv.ParseUint(strUserId, 10, 64)
		if err != nil {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse user ID")))
			return
		}

		deviceId, err := strconv.ParseUint(strDeviceId, 10, 64)
		if err != nil {
			httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse device ID")))
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyCodeId, uint(codeId)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, uint(userId)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyDeviceId, uint(deviceId)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyPlatform, "app"))

		logx.Infof("event_check_token, platform: %v, userId: %v, codeId: %v, deviceId: %v", "app", userId, codeId, deviceId)

		// Passthrough to next handler if need
		next(w, r)
	}
}
