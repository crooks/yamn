// vim: tabstop=2 shiftwidth=2

package main

import (
	"io"
	//"io/ioutil"
	"log"
	"os"
	"time"
)

const (
	version string = "0.1a"
	date_format string = "2006-01-02"
	key_validity_days int = 60
	max_frag_length = 10230
	maxChainLength = 10
	maxCopies = 5
	base64_line_wrap = 40
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
	logInit(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
	flags()
	if flag_client {
		mixprep()
	} else {
		Info.Println("Starting YAMN server")
		for {
			mailRead()
			poolRead()
			time.Sleep(60 * time.Second)
		}
	}
}
