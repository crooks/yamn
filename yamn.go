package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

const (
	version        string = "0.2c"
	dayLength      int    = 24 * 60 * 60 // Day in seconds
	maxFragLength         = 17910
	maxCopies             = 5
	base64LineWrap        = 64
	rfc5322date           = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortdate             = "2 Jan 2006"
)

var (
	// Trace loglevel
	Trace *log.Logger
	// Info loglevel
	Info *log.Logger
	// Warn loglevel
	Warn *log.Logger
	// Error loglevel
	Error *log.Logger
	// Pubring - Public Keyring
	Pubring *keymgr.Pubring
	// IDDb - Message ID log (replay protection)
	IDDb *idlog.IDLog
	// ChunkDb - Chunk database
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
	if cfg.General.LogToFile {
		logfile, err := os.OpenFile(
			cfg.Files.Logfile,
			os.O_RDWR|os.O_CREATE|os.O_APPEND,
			0640,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Error opening logfile: %s.\n",
				err,
			)
			os.Exit(1)
		}
		switch strings.ToLower(cfg.General.Loglevel) {
		case "trace":
			logInit(logfile,
				logfile,
				logfile,
				logfile,
			)
		case "info":
			logInit(ioutil.Discard,
				logfile,
				logfile,
				logfile,
			)
		case "warn":
			logInit(ioutil.Discard,
				ioutil.Discard,
				logfile,
				logfile,
			)
		case "error":
			logInit(ioutil.Discard,
				ioutil.Discard,
				ioutil.Discard,
				logfile,
			)
		default:
			fmt.Fprintf(
				os.Stderr,
				"Unknown loglevel: %s.  Assuming \"Info\".\n",
				cfg.General.Loglevel,
			)
			logInit(ioutil.Discard,
				logfile,
				logfile,
				logfile,
			)
		}
	} else {
		switch strings.ToLower(cfg.General.Loglevel) {
		case "trace":
			logInit(os.Stdout,
				os.Stdout,
				os.Stdout,
				os.Stderr,
			)
		case "info":
			logInit(ioutil.Discard,
				os.Stdout,
				os.Stdout,
				os.Stderr,
			)
		case "warn":
			logInit(ioutil.Discard,
				ioutil.Discard,
				os.Stdout,
				os.Stderr,
			)
		case "error":
			logInit(
				ioutil.Discard,
				ioutil.Discard,
				ioutil.Discard,
				os.Stderr,
			)
		default:
			fmt.Fprintf(
				os.Stderr,
				"Unknown loglevel: %s.  Assuming \"Info\".\n",
				cfg.General.Loglevel,
			)
			logInit(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
		} // End of stdout/stderr logging setup
	} // End of logging setup

	// If the debug flag is set, print the config in JSON format and then exit.
	if flagDebug {
		j, err := json.MarshalIndent(cfg, "", "    ")
		if err != nil {
			fmt.Printf("Debugging Error: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", j)
		os.Exit(0)
	}

	if flagClient {
		mixprep()
	} else if flagStdin {
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
	} else if flagRemailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else if flagDummy {
		injectDummy()
	}
	if flagSend {
		// Flush the outbound pool
		poolOutboundSend()
	}
}
