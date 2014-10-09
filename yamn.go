// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

const (
	version string = "0.1b"
	dayLength int = 24 * 60 * 60 // Day in seconds
	keyValidityDays int = 60
	maxFragLength = 10230
	maxChainLength = 10
	maxCopies = 5
	base64LineWrap = 40
	headerBytes = 512
	headersBytes = headerBytes * maxChainLength
	encHeadBytes = headersBytes - headerBytes
	bodyBytes = 10240
	messageBytes = headersBytes + bodyBytes
)

var (
	Trace	*log.Logger
	Info	*log.Logger
	Warn	*log.Logger
	Error	*log.Logger
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
	flags()
	if flag_client {
		mixprep()
	} else if flag_remailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Printf("Version: %s\n", version)
	}
}
