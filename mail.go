// vim: tabstop=2 shiftwidth=2

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
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

// parseFrom takes a mail address of the format Name <name@foo> and validates
// it.  If custom From headers are not allowed, it will be tweaked to conform
// with the Remailer's configuration.
func parseFrom(from string) (addy string) {
	addyList, err := mail.ParseAddressList(from)
	if err != nil {
		// The supplied address is invalid.  Use defaults instead.
		addy = fmt.Sprintf(
			"%s <%s>",
			cfg.Mail.OutboundName,
			cfg.Mail.OutboundAddy,
		)
		return
	}
	if cfg.Mail.CustomFrom {
		// Accept whatever was provided (it's already been validated by
		// ParseAddressList).
		addy = from
	} else {
		if len(addyList[0].Name) == 0 {
			addy = fmt.Sprintf(
				"%s <%s>",
				cfg.Mail.OutboundName,
				cfg.Mail.OutboundAddy,
			)
		} else {
			addy = fmt.Sprintf(
				"%s <%s>",
				addyList[0].Name,
				cfg.Mail.OutboundAddy,
			)
		}
	}
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
	msg.Header["From"] = []string{parseFrom(msg.Header["From"][0])}
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
		err = smtpRelay(payload, sendTo)
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

func smtpRelay(payload []byte, sendTo []string) (err error) {
	conf := new(tls.Config)
	conf.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
	conf.InsecureSkipVerify = true
	conf.MinVersion = tls.VersionSSL30
	conf.MaxVersion = tls.VersionTLS10
	serverAddr := fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		Warn.Printf("Error Dialing %s\n", err)
		return
	}

	client, err := smtp.NewClient(conn, cfg.Mail.SMTPRelay)
	if err != nil {
		Warn.Printf("Error SMTP connection: %s\n", err)
		return
	}
	// Test is the remote MTA supports STARTTLS
	ok, _ := client.Extension("STARTTLS")
	if ok && cfg.Mail.UseTLS {
		if err = client.StartTLS(conf); err != nil {
			Warn.Printf("Error performing StartTLS: %s\n", err)
			return
		}
	}
	// If AUTH is supported and a UserID and Password are configured, try to
	// authenticate to the remote MTA.
	ok, _ = client.Extension("AUTH")
	if ok && cfg.Mail.Username != "" && cfg.Mail.Password != "" {
		auth := smtp.PlainAuth(
			"",
			cfg.Mail.Username,
			cfg.Mail.Password,
			cfg.Mail.SMTPRelay,
		)
		if err = client.Auth(auth); err != nil {
			Warn.Printf("Error during AUTH %s\n", err)
			return
		}
	}
	if err = client.Mail(cfg.Mail.EnvelopeSender); err != nil {
		Warn.Printf("Error: %s\n", err)
		return
	}

	for _, addr := range sendTo {
		if err = client.Rcpt(addr); err != nil {
			Warn.Printf("Error: %s\n", err)
			return
		}
	}

	w, err := client.Data()
	if err != nil {
		Warn.Printf("Error: %s\n", err)
		return
	}

	_, err = w.Write(payload)
	if err != nil {
		Warn.Printf("Error: %s\n", err)
		return

	}

	err = w.Close()
	if err != nil {
		Warn.Printf("Error: %s\n", err)
		return

	}

	client.Quit()
	return
}

// sendmail invokes go's sendmail method
func sendmail(payload []byte, sendTo []string) (err error) {
	auth := smtp.PlainAuth(
		"",
		cfg.Mail.Username,
		cfg.Mail.Password,
		cfg.Mail.SMTPRelay)
	relay := fmt.Sprintf("%s:%d", cfg.Mail.SMTPRelay, cfg.Mail.SMTPPort)
	err = smtp.SendMail(relay, auth, cfg.Mail.EnvelopeSender, sendTo, payload)
	if err != nil {
		Warn.Println(err)
		return
	}
	return
}
