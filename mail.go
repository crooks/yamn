// vim: tabstop=2 shiftwidth=2

package main

import (
	"net/mail"
	"bytes"
	"fmt"
	"net/smtp"
)

func assemble(msg mail.Message) []byte {
	buf := new(bytes.Buffer)
	for h := range msg.Header {
		buf.WriteString(h + ": " + msg.Header.Get(h) + "\n")
	}
	buf.WriteString("\n")
	buf.ReadFrom(msg.Body)
	return buf.Bytes()
}

func SMTPRelay(payload []byte, sendto string) (err error) {
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort))
	if err != nil {
		Warn.Println(err)
		return
	}
	err = c.Mail(cfg.Mail.EnvelopeSender)
	if err != nil {
		Warn.Println(err)
		return
	}
	err = c.Rcpt(sendto)
	if err != nil {
		Warn.Println(err)
		return
	}
	wc, err := c.Data()
	if err != nil {
		Warn.Println(err)
		return
	}
	_, err = fmt.Fprintf(wc, string(payload))
	if err != nil {
		Warn.Println(err)
		return
	}
	err = wc.Close()
	if err != nil {
		Warn.Println(err)
		return
	}
	err = c.Quit()
	if err != nil {
		Warn.Println(err)
		return
	}
	return
}

// sendmail invokes go's sendmail method
func sendmail(payload []byte, sendto string) (err error) {
	auth := smtp.PlainAuth("", cfg.Mail.SMTPUsername, cfg.Mail.SMTPPassword, cfg.Mail.SMTPRelay)
	relay := fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort)
	err = smtp.SendMail(relay, auth, cfg.Mail.EnvelopeSender, []string{sendto}, payload)
	if err != nil {
		Warn.Println(err)
		return
	}
	return
}
