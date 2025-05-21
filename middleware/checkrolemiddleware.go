package middleware

import (
	"net/http"

	"github.com/myimilo/resthelper"
	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

type CheckRoleMiddleware struct {
	allowedRoles []string
}

func NewCheckRoleMiddleware(allowedRoles ...string) *CheckRoleMiddleware {
	return &CheckRoleMiddleware{
		allowedRoles: allowedRoles,
	}
}

func (m *CheckRoleMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userRole := getUserRole(r)

		if !m.isRoleAllowed(userRole) {
			logx.Errorf("check role failed, user role: %v, allowed roles: %v", userRole, m.allowedRoles)
			httpx.Error(w, errorx.NewError(http.StatusForbidden, errorx.WithMessage("无权操作")))
			return
		}

		next(w, r)
	}
}

func (m *CheckRoleMiddleware) isRoleAllowed(userRole string) bool {
	if len(m.allowedRoles) == 0 {
		return true
	}

	for _, role := range m.allowedRoles {
		if role == userRole {
			return true
		}
	}

	return false
}

func getUserRole(r *http.Request) string {
	ctx := r.Context()
	userRole, ok := ctx.Value(resthelper.ContextKeyUserRole).(string)
	if !ok {
		return resthelper.RoleUser
	}

	return userRole
}
