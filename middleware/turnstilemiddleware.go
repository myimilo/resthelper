package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/myimilo/resthelper/errorx"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest/httpx"
)

const (
	TurnstileVerifyURL   = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	TurnstileTokenHeader = "X-Turnstile-Token"
)

type TurnstileMiddleware struct {
	SecretKey string
	PassKey   string
}

type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
}

func NewTurnstileMiddleware(secretKey, passKey string) *TurnstileMiddleware {
	return &TurnstileMiddleware{
		SecretKey: secretKey,
		PassKey:   passKey,
	}
}

func (m *TurnstileMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(TurnstileTokenHeader)
		if m.PassKey != "" && token == m.PassKey {
			next(w, r)
			return
		}

		if token == "" {
			httpx.Error(w, errorx.NewError(http.StatusForbidden, errorx.WithMessage("turnstile")))
			return
		}

		valid, err := m.verifyTurnstileToken(token)
		if err != nil {
			httpx.Error(w, errorx.NewError(http.StatusForbidden, errorx.WithMessage("turnstile")))
			return
		}

		if !valid {
			httpx.Error(w, errorx.NewError(http.StatusForbidden, errorx.WithMessage("turnstile")))
			return
		}

		next(w, r)
	}
}

func (m *TurnstileMiddleware) verifyTurnstileToken(token string) (bool, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	formData := url.Values{
		"secret":   {m.SecretKey},
		"response": {token},
	}

	resp, err := client.PostForm(TurnstileVerifyURL, formData)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var turnstileResp TurnstileResponse
	if err := json.Unmarshal(body, &turnstileResp); err != nil {
		return false, err
	}

	if !turnstileResp.Success {
		logx.Errorf("turnstile verify failed, token: %s, error: %v", token, turnstileResp.ErrorCodes)
	}

	return turnstileResp.Success, nil
}
