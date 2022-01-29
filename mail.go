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
	"strings"
	"time"

	"github.com/Masterminds/log-go"
)

func assemble(msg mail.Message) []byte {
	buf := new(bytes.Buffer)
	for h := range msg.Header {
		if strings.HasPrefix(h, "Yamn-") {
			log.Errorf("Ignoring internal mail header in assemble phase: %s", h)
		} else {
			buf.WriteString(h + ": " + msg.Header.Get(h) + "\n")
			//fmt.Printf("%s: %s\n", h, msg.Header.Get(h))
		}
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
		log.Warnf("Failed to parse header: %s", header)
	}
	for _, addy := range addyList {
		addys = append(addys, addy.Address)
	}
	return
}

type emailAddress struct {
	name   string
	domain string
}

// splitAddress splits an email address into its component parts
func splitEmailAddress(addy string) (e emailAddress, err error) {
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
	e.name = components[0]
	e.domain = components[1]
	return
}

// mxLookup returns the responsible MX for a given email address
func mxLookup(email string) (relay string, err error) {
	emailParts, err := splitEmailAddress(email)
	if err != nil {
		// Failed to ascertain domain name from email address
		return
	}
	mxRecords, err := net.LookupMX(emailParts.domain)
	if err != nil {
		relay = emailParts.domain
		log.Tracef(
			"DNS MX lookup failed for %s.  Using hostname.",
			emailParts.domain,
		)
		err = nil
		return
	}
	for _, mx := range mxRecords {
		if !cfg.Mail.OnionRelay {
			// We don't want no onions!
			if strings.HasSuffix(mx.Host, ".onion.") {
				// Ignore the onion, find another.
				continue
			}
		}
		relay = mx.Host
		break
	}
	if relay == "" {
		// No suitable relays found, use the hostname.
		log.Infof(
			"No valid MX records found for %s. Using hostname.",
			emailParts.domain,
		)
		relay = emailParts.domain
		return
	}
	log.Tracef(
		"DNS lookup: Hostname=%s, MX=%s",
		emailParts.domain,
		relay,
	)
	return
}

// parseFrom takes a mail address of the format Name <name@foo> and validates
// it.  If custom From headers are not allowed, it will be tweaked to conform
// with the Remailer's configuration.
func parseFrom(h mail.Header) []string {
	from, err := h.AddressList("From")
	if err != nil {
		// The supplied address is invalid.  Use defaults instead.
		return []string{fmt.Sprintf(
			"%s <%s>",
			cfg.Mail.OutboundName,
			cfg.Mail.OutboundAddy,
		)}
	}
	if len(from) == 0 {
		// The address list is empty so return defaults
		return []string{fmt.Sprintf(
			"%s <%s>",
			cfg.Mail.OutboundName,
			cfg.Mail.OutboundAddy,
		)}
	}
	if cfg.Mail.CustomFrom {
		// Accept whatever was provided (it's already been validated by
		// AddressList).
		return []string{fmt.Sprintf(
			"%s <%s>",
			from[0].Name,
			from[0].Address,
		)}
	}
	if len(from[0].Name) == 0 {
		return []string{fmt.Sprintf(
			"%s <%s>",
			cfg.Mail.OutboundName,
			cfg.Mail.OutboundAddy,
		)}
	}
	return []string{fmt.Sprintf(
		"%s <%s>",
		from[0].Name,
		cfg.Mail.OutboundAddy,
	)}
}

// Read a file from the outbound pool and mail it
func mailPoolFile(filename string) (delFlag bool, err error) {
	// This flag implies that, by default, we don't delete pool messages
	delFlag = false

	f, err := os.Open(filename)
	if err != nil {
		log.Errorf("Failed to read file for mailing: %s", err)
		return
	}
	defer f.Close()

	msg, err := mail.ReadMessage(f)
	if err != nil {
		log.Errorf("Failed to process mail file: %s", err)
		// If we can't process it, it'll never get sent.  Mark for delete.
		delFlag = true
		return
	}

	// Test for a Pooled Date header in the message.
	pooledHeader := msg.Header.Get("Yamn-Pooled-Date")
	if pooledHeader == "" {
		// Legacy condition.  All current versions apply this header.
		log.Warn("No Yamn-Pooled-Date header in message")
	} else {
		var pooledDate time.Time
		pooledDate, err = time.Parse(shortdate, pooledHeader)
		if err != nil {
			log.Errorf("%s: Failed to parse Yamn-Pooled-Date: %s", filename, err)
			return
		}
		age := daysAgo(pooledDate)
		if age > cfg.Pool.MaxAge {
			// The message has expired.  Give up trying to send it.
			log.Infof(
				"%s: Refusing to mail pool file. Exceeds max age of %d days",
				filename,
				cfg.Pool.MaxAge,
			)
			// Set deletion flag.  We don't want to retain old
			// messages forever.
			delFlag = true
			return
		}
		if age > 0 {
			log.Tracef("Mailing pooled file that's %d days old.", age)
		}
		// Delete the internal header we just tested.
		delete(msg.Header, "Yamn-Pooled-Date")
	}

	// Add some required headers to the message.
	msg.Header["Date"] = []string{time.Now().Format(rfc5322date)}
	msg.Header["Message-Id"] = []string{messageID()}
	msg.Header["From"] = parseFrom(msg.Header)
	sendTo := headToAddy(msg.Header, "To")
	sendTo = append(sendTo, headToAddy(msg.Header, "Cc")...)
	if len(sendTo) == 0 {
		err = fmt.Errorf("%s: No email recipients found", filename)
		// No point in repeatedly trying to resend a malformed file.
		delFlag = true
		return
	}
	// There is an assumption here that all errors from mailBytes should not
	// delete pool files (delFlag is false by default).
	err = mailBytes(assemble(*msg), sendTo)
	return
}

// Mail a byte payload to a given address
func mailBytes(payload []byte, sendTo []string) (err error) {
	// Test if the message is destined for the local remailer
	log.Tracef("Message recipients are: %s", strings.Join(sendTo, ","))
	if cfg.Mail.Outfile {
		var f *os.File
		filename := randPoolFilename("outfile-")
		log.Tracef("Writing output to %s", filename)
		f, err = os.Create(filename)
		if err != nil {
			log.Warnf("Pool file creation failed: %s\n", err)
			return
		}
		defer f.Close()
		_, err = f.WriteString(string(payload))
		if err != nil {
			log.Warnf("Outfile write failed: %s\n", err)
			return
		}
	} else if cfg.Mail.Pipe != "" {
		err = execSend(payload, cfg.Mail.Pipe)
		if err != nil {
			log.Warn("Email pipe failed")
			return
		}
	} else if cfg.Mail.Sendmail {
		err = sendmail(payload, sendTo)
		if err != nil {
			log.Warn("Sendmail failed")
			return
		}
	} else {
		err = smtpRelay(payload, sendTo)
		if err != nil {
			log.Warn("SMTP relay failed")
			return
		}
	}
	return
}

// Pipe mail to an external command (E.g. sendmail -t)
func execSend(payload []byte, execCmd string) (err error) {
	sendmail := new(exec.Cmd)
	sendmail.Args = strings.Fields(execCmd)
	sendmail.Path = sendmail.Args[0]

	stdin, err := sendmail.StdinPipe()
	if err != nil {
		log.Errorf("%s: %s", execCmd, err)
		return
	}
	defer stdin.Close()
	sendmail.Stdout = os.Stdout
	sendmail.Stderr = os.Stderr
	err = sendmail.Start()
	if err != nil {
		log.Errorf("%s: %s", execCmd, err)
		return
	}
	stdin.Write(payload)
	stdin.Close()
	err = sendmail.Wait()
	if err != nil {
		log.Errorf("%s: %s", execCmd, err)
		return
	}
	return
}

func smtpRelay(payload []byte, sendTo []string) (err error) {
	conf := new(tls.Config)
	//conf.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
	conf.InsecureSkipVerify = true
	//conf.MinVersion = tls.VersionSSL30
	//conf.MaxVersion = tls.VersionTLS10
	relay := cfg.Mail.SMTPRelay
	port := cfg.Mail.SMTPPort

	/*
		The following section tries to get the MX record for the
		recipient email address, when there is only a single recipient.
		If it succeeds, the email will be sent directly to the
		recipient MX.
	*/
	if cfg.Mail.MXRelay && len(sendTo) == 1 {
		log.Tracef("DNS lookup of MX record for %s.", sendTo[0])
		mx, err := mxLookup(sendTo[0])
		if err == nil {
			log.Tracef(
				"Doing direct relay for %s to %s:25.",
				sendTo[0],
				mx,
			)
			relay = mx
			port = 25
		}
	}
	serverAddr := fmt.Sprintf("%s:%d", relay, port)

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Warnf("Dial Error: Server=%s, Error=%s", serverAddr, err)
		return
	}

	client, err := smtp.NewClient(conn, relay)
	if err != nil {
		log.Warnf(
			"SMTP Connection Error: Server=%s, Error=%s",
			serverAddr,
			err,
		)
		return
	}
	// Test if the remote MTA supports STARTTLS
	ok, _ := client.Extension("STARTTLS")
	if ok && cfg.Mail.UseTLS {
		if err = client.StartTLS(conf); err != nil {
			log.Warnf(
				"Error performing STARTTLS: Server=%s, Error=%s",
				serverAddr,
				err,
			)
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
			log.Warnf("Auth Error:  Server=%s, Error=%s", serverAddr, err)
			return
		}
	}
	// Remailer.Address is a legacy setting as clients may also need to
	// set the sender address if their ISPs MTA demands it's valid.
	// TODO remove cfg.Remailer.Address in a later version (27/04/2015)
	var sender string
	if cfg.Mail.Sender != "" {
		sender = cfg.Mail.Sender
	} else {
		sender = cfg.Remailer.Address
	}
	if err = client.Mail(sender); err != nil {
		log.Warnf("SMTP Error: Server=%s, Error=%s", serverAddr, err)
		return
	}

	for _, addr := range sendTo {
		if err = client.Rcpt(addr); err != nil {
			log.Warnf("Error: %s\n", err)
			return
		}
	}

	w, err := client.Data()
	if err != nil {
		log.Warnf("Error: %s\n", err)
		return
	}

	_, err = w.Write(payload)
	if err != nil {
		log.Warnf("Error: %s\n", err)
		return

	}

	err = w.Close()
	if err != nil {
		log.Warnf("Error: %s\n", err)
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
	err = smtp.SendMail(relay, auth, cfg.Remailer.Address, sendTo, payload)
	if err != nil {
		log.Warn(err)
		return
	}
	return
}
