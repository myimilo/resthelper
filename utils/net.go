package utils

import (
	"net/http"
	"strings"
)

func GetIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip == "" {
		if ip := r.Header.Get("X-Real-Ip"); ip != "" {
			return ip
		}
		pieces := strings.SplitN(r.RemoteAddr, ":", 2)
		if len(pieces) >= 1 {
			return pieces[0]
		}
	} else {
		pieces := strings.SplitN(ip, ",", 2)
		if len(pieces) >= 1 {
			return pieces[0]
		}
	}

	return ""
}
