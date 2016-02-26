// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	version        string = "0.2b"
	dayLength      int    = 24 * 60 * 60 // Day in seconds
	maxFragLength         = 17910
	maxCopies             = 5
	base64LineWrap        = 64
	rfc5322date           = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortdate             = "2 Jan 2006"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warn    *log.Logger
	Error   *log.Logger
	Pubring *keymgr.Pubring
	IdDb    *idlog.IDLog
	ChunkDb *Chunk
)

func logInit(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warnHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"Trace: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"Info: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warn = log.New(warnHandle,
		"Warn: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"Error: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	var err error
	flags()
	switch strings.ToLower(cfg.Remailer.Loglevel) {
	case "trace":
		logInit(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
	case "info":
		logInit(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
	case "warn":
		logInit(ioutil.Discard, ioutil.Discard, os.Stdout, os.Stderr)
	case "error":
		logInit(ioutil.Discard, ioutil.Discard, ioutil.Discard, os.Stderr)
	default:
		fmt.Fprintf(os.Stderr, "Unknown loglevel: %s\n", cfg.Remailer.Loglevel)
	}
	if flag_client {
		mixprep()
	} else if flag_stdin {
		dir := maildir.Dir(cfg.Files.Maildir)
		newmsg, err := dir.NewDelivery()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		stdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		newmsg.Write(stdin)
		newmsg.Close()
	} else if flag_remailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else if flag_dummy {
		injectDummy()
	}
	if flag_send {
		// Flush the outbound pool
		poolOutboundSend()
	}
}
