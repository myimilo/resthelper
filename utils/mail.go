package utils

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

func SendEmail(smtpHost string, smtpPort int, from, password string, to []string, subject, body string) error {
	auth := smtp.PlainAuth("", from, password, smtpHost)

	message := fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n"+
		"\r\n"+
		"%s\r\n", to[0], subject, body)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpHost,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", smtpHost, smtpPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}

	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %v", err)
	}

	if err = client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}

	for _, recipient := range to {
		if err = client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient: %v", err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get write stream: %v", err)
	}
	_, err = wc.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write email content: %v", err)
	}

	err = wc.Close()
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	err = client.Quit()
	if err != nil {
		return fmt.Errorf("failed to quit SMTP: %v", err)
	}

	return nil
}
