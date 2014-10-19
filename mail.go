// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"strings"
	"net/mail"
	"bytes"
	"fmt"
	"net/smtp"
	"errors"
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

// testMail vets outbound messages to final recipients
func testMail(b []byte) (recipients []string, err error) {
	f := bytes.NewReader(b)
	msg, err := mail.ReadMessage(f)
	if err != nil {
		Trace.Printf("Outbound read failure: %s", err)
		return
	}
	var exists bool
	h := msg.Header
	_, exists = h["To"]
	if ! exists {
		err = errors.New("No recipient specified in final delivery")
		Trace.Println(err)
		return
	}
	addys, err := h.AddressList("To")
	if err != nil {
		return
	}
	for _, addy := range addys {
		recipients = append(recipients, addy.Address)
	}
	return
}

func mailFile(filename string) (err error) {
	var f *os.File
	f, err = os.Open(filename)
	defer f.Close()
	addy := make([]byte, 80)
	var bytesRead int
	bytesRead, err = f.Read(addy)
	if err != nil {
		Warn.Printf("Failed to read address from %s: %s", filename, err)
	}
	if bytesRead != 80 {
		Error.Println("Incorrect byte count reading email address from",
			fmt.Sprintf("%s. Expected=80, Got=%d", filename, bytesRead))
	}
	sendto := strings.TrimRight(string(addy), "\x00")
	Trace.Printf("Pool recipient is: %s", sendto)
	payload := make([]byte, messageBytes)
	bytesRead, err = f.Read(payload)
	if err != nil {
		Warn.Printf("Failed to read payload from %s: %s", filename, err)
	}
	if bytesRead != messageBytes {
		Error.Println("Incorrect byte count reading payload from",
			fmt.Sprintf("%s. Expected=%d, Got=%d", filename, messageBytes, bytesRead))
	}
	err = cutmarks(payload, sendto)
	if err != nil {
		Warn.Printf("Cutmarking failed: %s", err)
		return
	}
	return
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
