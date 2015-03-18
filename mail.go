// vim: tabstop=2 shiftwidth=2

package main

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
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

// headToAddy parses a header containing email addresses
func headToAddy(h mail.Header, header string) (addys []string) {
	_, exists := h[header]
	if !exists {
		return
	}
	addyList, err := h.AddressList(header)
	if err != nil {
		Warn.Printf("Failed to parse header: %s", header)
	}
	for _, addy := range addyList {
		addys = append(addys, addy.Address)
	}
	return
}

// splitAddress splits an email address into its component parts
func splitAddress(addy string) (name, domain string, err error) {
	// Email addresses must have '@' signs in them.
	if !strings.Contains(addy, "@") {
		err = fmt.Errorf("%s: Email address contains no '@'", addy)
		return
	}
	components := strings.Split(addy, "@")
	if len(components) != 2 {
		err = fmt.Errorf("%s: Malformed email address", addy)
		return
	}
	name = components[0]
	domain = components[1]
	return
}

// Read a file from the outbound pool and mail it
func mailPoolFile(filename string) error {
	var err error
	f, err := os.Open(filename)
	if err != nil {
		Error.Printf("Failed to read file for mailing: %s", err)
		return err
	}
	defer f.Close()
	msg, err := mail.ReadMessage(f)
	if err != nil {
		Error.Printf("Failed to process mail file: %s", err)
		return err
	}
	msg.Header["Date"] = []string{time.Now().Format(rfc5322date)}
	sendTo := headToAddy(msg.Header, "To")
	sendTo = append(sendTo, headToAddy(msg.Header, "Cc")...)
	if len(sendTo) == 0 {
		err = fmt.Errorf("%s: No email recipients found", filename)
		return err
	}
	return mailBytes(assemble(*msg), sendTo)
}

// Mail a byte payload to a given address
func mailBytes(payload []byte, sendTo []string) (err error) {
	// Test if the message is destined for the local remailer
	Trace.Printf("Message recipients are: %s", strings.Join(sendTo, ","))
	if cfg.Mail.Outfile {
		var f *os.File
		filename := randPoolFilename("outfile-")
		f, err = os.Create(path.Join(cfg.Files.Pooldir, filename))
		defer f.Close()
		_, err = f.WriteString(string(payload))
		if err != nil {
			Warn.Printf("Outfile write failed: %s\n", err)
			return
		}
	} else if cfg.Mail.Pipe != "" {
		execSend(payload, cfg.Mail.Pipe)
	} else if cfg.Mail.Sendmail {
		err = sendmail(payload, sendTo)
		if err != nil {
			Warn.Println("Sendmail failed")
			return
		}
	} else {
		err = SMTPRelay(payload, sendTo)
		if err != nil {
			Warn.Println("SMTP relay failed")
			return
		}
	}
	return
}

// Pipe mail to an external command (E.g. sendmail -t)
func execSend(payload []byte, execCmd string) {
	sendmail := new(exec.Cmd)
	sendmail.Args = strings.Fields(execCmd)
	sendmail.Path = sendmail.Args[0]

	stdin, err := sendmail.StdinPipe()
	if err != nil {
		panic(err)
	}
	defer stdin.Close()
	sendmail.Stdout = os.Stdout
	sendmail.Stderr = os.Stderr
	err = sendmail.Start()
	if err != nil {
		panic(err)
	}
	stdin.Write(payload)
	stdin.Close()
	err = sendmail.Wait()
	if err != nil {
		//Warn.Printf("%s: %s", execCmd, err)
		panic(err)
	}
}

func SMTPRelay(payload []byte, sendTo []string) (err error) {
	c, err := smtp.Dial(
		fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort))
	if err != nil {
		Warn.Println(err)
		return
	}
	err = c.Mail(cfg.Mail.EnvelopeSender)
	if err != nil {
		Warn.Println(err)
		return
	}
	for _, s := range sendTo {
		err = c.Rcpt(s)
		if err != nil {
			Warn.Println(err)
			continue
		}
		wc, err := c.Data()
		if err != nil {
			Warn.Println(err)
			continue
		}
		_, err = fmt.Fprintf(wc, string(payload))
		if err != nil {
			Warn.Println(err)
			continue
		}
		err = wc.Close()
		if err != nil {
			Warn.Println(err)
			continue
		}
	}
	err = c.Quit()
	if err != nil {
		Warn.Println(err)
		return
	}
	return
}

// sendmail invokes go's sendmail method
func sendmail(payload []byte, sendTo []string) (err error) {
	auth := smtp.PlainAuth(
		"",
		cfg.Mail.SMTPUsername,
		cfg.Mail.SMTPPassword,
		cfg.Mail.SMTPRelay)
	relay := fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort)
	err = smtp.SendMail(relay, auth, cfg.Mail.EnvelopeSender, sendTo, payload)
	if err != nil {
		Warn.Println(err)
		return
	}
	return
}
