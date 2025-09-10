package utils

import (
	"net"
	"net/http"
	"strings"
)

func GetIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip == "" {
		if ip := r.Header.Get("X-Real-Ip"); ip != "" {
			return ip
		}
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
			return r.RemoteAddr
		} else {
			return ip
		}
	} else {
		pieces := strings.SplitN(ip, ",", 2)
		if len(pieces) >= 1 {
			return pieces[0]
		}
	}

	return ""
}

func ExtractApiKey(r *http.Request) string {
	// Try X-API-Key header first
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	// Try Authorization header with Bearer format
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		fields := strings.Fields(authHeader)
		if len(fields) == 2 && strings.ToLower(fields[0]) == "bearer" {
			return fields[1]
		}
	}

	return ""
}
