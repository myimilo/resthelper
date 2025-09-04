package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/myimilo/resthelper/utils"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckUserApiKeyMiddleware struct {
	redis         *redis.Redis
	apiKeyPrefix  string
	balancePrefix string
}

func NewCheckUserApiKeyMiddleware(redis *redis.Redis, apiKeyPrefix, balancePrefix string) *CheckUserApiKeyMiddleware {
	return &CheckUserApiKeyMiddleware{
		redis:         redis,
		apiKeyPrefix:  apiKeyPrefix,
		balancePrefix: balancePrefix,
	}
}

func (m *CheckUserApiKeyMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := utils.ExtractApiKey(r)
		if apiKey == "" {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		// Get user ID from API key mapping
		userId, err := m.getUserIdFromApiKey(apiKey)
		if err != nil || userId == 0 {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

		if m.balancePrefix != "" {
			// Check user balance
			v, err := m.redis.Get(fmt.Sprintf("%s%d", m.balancePrefix, userId))
			if err != nil || v == "" {
				httpx.Error(w, errorx.NewError(http.StatusPaymentRequired, errorx.WithMessage("Insufficient balance")))
				return
			}

			balance, err := strconv.ParseFloat(v, 64)
			if err != nil {
				httpx.Error(w, errorx.NewError(http.StatusInternalServerError, errorx.WithMessage("Failed to parse balance")))
				return
			}

			if balance <= 0 {
				httpx.Error(w, errorx.NewError(http.StatusPaymentRequired, errorx.WithMessage("Insufficient balance")))
				return
			}

			logx.Infof("event_check_apikey_balance, apiKey: %s, userId: %v, balance: %v", apiKey[:8]+"***", userId, balance)
		} else {
			logx.Infof("event_check_apikey, apiKey: %s, userId: %v", apiKey[:8]+"***", userId)
		}

		// Set user context for downstream handlers
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyUserId, userId))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyCodeId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyDeviceId, uint(0)))
		r = r.WithContext(context.WithValue(r.Context(), resthelper.ContextKeyPlatform, "api"))

		next(w, r)
	}
}

func (m *CheckUserApiKeyMiddleware) getUserIdFromApiKey(apiKey string) (uint, error) {
	// Get user ID from Redis using API key as the key
	// Format: apiKeyPrefix:apiKey -> userId
	userIdStr, err := m.redis.Get(fmt.Sprintf("%s%s", m.apiKeyPrefix, apiKey))
	if err != nil {
		return 0, err
	}

	if userIdStr == "" {
		return 0, fmt.Errorf("api key not found")
	}

	userId, err := strconv.ParseUint(userIdStr, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint(userId), nil
}
