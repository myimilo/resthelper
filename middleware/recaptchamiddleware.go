package middleware

import (
	"net/http"
	"net/url"

	"github.com/zeromicro/go-zero/core/logx"
)

type RecaptchaResponse struct {
	RiskAnalysis    *RiskAnalysis    `json:"riskAnalysis"`
	TokenProperties *TokenProperties `json:"tokenProperties"`
	Error           *RecaptchaError  `json:"error"`
}

type RecaptchaError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type TokenProperties struct {
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalidReason"`
}

type RiskAnalysis struct {
	Score float64 `json:"score"`
}

type RecaptchaMiddleware struct {
	Address string
	Secret  string
	Passkey string
	Proxy   string
	Client  *http.Client
}

func NewRecaptchaMiddleware(address, secret, passkey, proxy string) *RecaptchaMiddleware {
	client := &http.Client{}
	if proxy != "" {
		if proxyURL, err := url.Parse(proxy); err != nil {
			logx.Errorf("failed to parse proxy: %v", err)
		} else {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	return &RecaptchaMiddleware{
		Address: address, // api path, "https://www.google.com/recaptcha/api/siteverify"
		Secret:  secret,  // secret allocated by google
		Passkey: passkey, // bypass the token verify
		Proxy:   proxy,   // proxy for the request
		Client:  client,
	}
}

func (m *RecaptchaMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: implement recaptcha middleware
		next(w, r)
	}
}
