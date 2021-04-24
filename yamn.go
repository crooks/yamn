package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/apex/log/handlers/logfmt"
	"github.com/apex/log/handlers/text"
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
	// Pubring - Public Keyring
	Pubring *keymgr.Pubring
	// IDDb - Message ID log (replay protection)
	IDDb *idlog.IDLog
	// ChunkDb - Chunk database
	ChunkDb *Chunk
)

func main() {
	var err error
	flags()
	if cfg.General.LogToFile {
		logfile, err := os.OpenFile(cfg.Files.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Error opening logfile: %s.\n",
				err,
			)
			os.Exit(1)
		}
		log.SetHandler(logfmt.New(logfile))
	} else {
		log.SetHandler(text.New(os.Stderr))
	}
	log.SetLevelFromString(strings.ToLower(cfg.General.Loglevel))

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
