package resthelper

const SessionName = "session"

type contextKey int

const (
	ContextKeySession contextKey = iota + 1
	ContextKeyUserId
	ContextKeyCodeId
	ContextKeyDeviceId
	ContextKeyPlatform
	ContextKeyUserRole
)

const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)
