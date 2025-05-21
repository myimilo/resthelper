package middleware

import (
	"net/http"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckAdminMiddleware struct{}

func NewCheckAdminMiddleware() *CheckAdminMiddleware {
	return &CheckAdminMiddleware{}
}

func (m *CheckAdminMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userRole := getUserRole(r)

		if userRole != resthelper.RoleAdmin {
			logx.Errorf("check admin role failed, user role: %v", userRole)
			httpx.Error(w, errorx.NewError(http.StatusForbidden, errorx.WithMessage("无权操作，需要管理员权限")))
			return
		}

		next(w, r)
	}
}
