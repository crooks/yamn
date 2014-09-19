// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"net/mail"
	"bytes"
	"fmt"
	"strings"
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

func import_msg(filename string) []byte {
	var err error
	f, err := os.Open(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Unable to open file\n", filename)
		os.Exit(1)
	}
	msg, err := mail.ReadMessage(f)
	if err != nil {
		panic(err)
	}
	if flag_to != "" {
		msg.Header["To"][0] = flag_to
		if ! strings.Contains(flag_to, "@") {
			fmt.Fprintf(os.Stderr, "%s: Recipient doesn't appear to be an email address\n", flag_to)
		}
	}
	if flag_subject != "" {
		msg.Header["Subject"][0] = flag_subject
	}
	return assemble(*msg)
}

func smtprelay(payload []byte, sendto string) {
	var err error
	c, err := smtp.Dial(fmt.Sprintf("%s:%d", cfg.Mail.Smtprelay, cfg.Mail.Smtpport))
	if err != nil {
		panic(err)
	}
	err = c.Mail(cfg.Mail.Envsender)
	if err != nil {
		panic(err)
	}
	err = c.Rcpt(sendto)
	if err != nil {
		panic(err)
	}
	wc, err := c.Data()
	if err != nil {
		panic(err)
	}
	_, err = fmt.Fprintf(wc, string(payload))
	if err != nil {
		panic(err)
	}
	err = wc.Close()
	if err != nil {
		panic(err)
	}
	err = c.Quit()
	if err != nil {
		panic(err)
	}
}

// sendmail invokes go's sendmail method
func sendmail(payload []byte, sendto string) {
	var err error
	auth := smtp.PlainAuth("", cfg.Mail.Smtpusername, cfg.Mail.Smtppassword, cfg.Mail.Smtprelay)
	relay := fmt.Sprintf("%s:%d", cfg.Mail.Smtprelay, cfg.Mail.Smtpport)
	err = smtp.SendMail(relay, auth, cfg.Mail.Envsender, []string{sendto}, payload)
	if err != nil {
		panic(err)
	}
}
