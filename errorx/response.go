package errorx

import "net/http"

// referto https://cloud.google.com/apis/design

type Detail struct {
	Reason   string                 `json:"reason"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type Error struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Status  string   `json:"status,omitempty"`
	Details []Detail `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error Error `json:"error"`
}

func (e *Error) Error() string {
	return e.Message
}

type errorOption func(*Error)

func WithMessage(message string) errorOption {
	return func(e *Error) {
		e.Message = message
	}
}

func WithStatus(status string) errorOption {
	return func(e *Error) {
		e.Status = status
	}
}

func WithDetails(detail Detail) errorOption {
	return func(e *Error) {
		e.Details = append(e.Details, detail)
	}
}

func WithDetailReasons(reason string) errorOption {
	return func(e *Error) {
		e.Details = append(e.Details, Detail{Reason: reason})
	}
}

func NewError(code int, opts ...errorOption) error {
	err := Error{Code: code, Status: http.StatusText(code)}
	for _, opt := range opts {
		if opt != nil {
			opt(&err)
		}
	}
	return &err
}
