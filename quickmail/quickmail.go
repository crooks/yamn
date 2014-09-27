// vim: tabstop=2 shiftwidth=2

package quickmail

import (
	"fmt"
	"bytes"
	"os"
	"errors"
)

type message struct {
	headers map[string]string
	Prefix string
	Filename string
	Suffix string
	SMTP struct {
		User string
		Password string
		Relay string
		Port int
	}
}

func NewMessage() *message {
	return &message{headers: make(map[string]string)}
}

func (m message) Set(head, content string) {
	m.headers[head] = content
}

func (m message) Get(head string) (string) {
	return m.headers[head]
}

func (m message) Del(head string) {
	delete(m.headers, head)
}

func (m *message) Text(t string) {
	m.Prefix += t
}

func (m message) Compile() (b []byte, err error) {
	var ok bool
	_, ok = m.headers["From"]
	if ! ok {
		err = errors.New("Compulsory From header not defined")
		return
	}
	_, ok = m.headers["To"]
	if ! ok {
		err = errors.New("Compulsory To header not defined")
		return
	}
	buf := new(bytes.Buffer)
	for h := range(m.headers) {
		buf.WriteString(fmt.Sprintf("%s: %s\n", h, m.headers[h]))
	}
	buf.WriteString("\n")
	if m.Prefix != "" {
		buf.WriteString(m.Prefix)
		buf.WriteString("\n")
	}
	if m.Filename != "" {
		var f *os.File
		f, err = os.Open(m.Filename)
		if err != nil {
			return
		}
		defer f.Close()
		_, err = buf.ReadFrom(f)
		buf.WriteString("\n")
	}
	if m.Suffix != "" {
		buf.WriteString(m.Suffix)
		buf.WriteString("\n")
	}
	b = buf.Bytes()
	return
}
