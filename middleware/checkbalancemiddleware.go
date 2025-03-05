package middleware

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckBalanceMiddleware struct {
	redis         *redis.Redis
	balancePrefix string
}

func NewCheckBalanceMiddleware(redis *redis.Redis, balancePrefix string) *CheckBalanceMiddleware {
	return &CheckBalanceMiddleware{
		redis:         redis,
		balancePrefix: balancePrefix,
	}
}

// check login (from app) middleware
func (m *CheckBalanceMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userId, ok := r.Context().Value(resthelper.ContextKeyUserId).(uint)
		if !ok || userId == 0 {
			httpx.Error(w, errorx.NewError(http.StatusUnauthorized))
			return
		}

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

		if balance < 0 {
			httpx.Error(w, errorx.NewError(http.StatusPaymentRequired, errorx.WithMessage("Insufficient balance")))
			return
		}

		logx.Infof("event_check_balance, userId: %v, balance: %v", userId, balance)

		// Passthrough to next handler if need
		next(w, r)
	}
}
