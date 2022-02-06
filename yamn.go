package main

import (
	"fmt"
	"io/ioutil"
	stdlog "log"
	"os"

	"github.com/Masterminds/log-go"
	"github.com/crooks/jlog"
	"github.com/crooks/yamn/config"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

const (
	version        string = "0.2.6"
	dayLength      int    = 24 * 60 * 60 // Day in seconds
	maxFragLength         = 17910
	maxCopies             = 5
	base64LineWrap        = 64
	rfc5322date           = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortdate             = "2 Jan 2006"
)

var (
	// flags - Command line flags
	flag *config.Flags
	// cfg - Config parameters
	cfg *config.Config
	// Pubring - Public Keyring
	Pubring *keymgr.Pubring
	// IDDb - Message ID log (replay protection)
	IDDb *idlog.IDLog
	// ChunkDb - Chunk database
	ChunkDb *Chunk
)

func main() {
	var err error
	flag, cfg = config.GetCfg()
	if flag.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	// If the debug flag is set, print the config and exit
	if flag.Debug {
		y, err := cfg.Debug()
		if err != nil {
			fmt.Printf("Debugging Error: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", y)
		os.Exit(0)
	}

	// Set up logging
	loglevel, err := log.Atoi(cfg.General.Loglevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: Unknown loglevel", cfg.General.Loglevel)
		os.Exit(1)
	}
	// If we're logging to a file, open the file and redirect output to it
	if cfg.General.LogToFile && cfg.General.LogToJournal {
		fmt.Fprintln(os.Stderr, "Cannot log to file and journal")
		os.Exit(1)
	} else if cfg.General.LogToFile {
		logfile, err := os.OpenFile(cfg.Files.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Error opening logfile: %v", cfg.Files.Logfile, err)
			os.Exit(1)
		}
		stdlog.SetOutput(logfile)
		log.Current = log.StdLogger{Level: loglevel}
	} else if cfg.General.LogToJournal {
		log.Current = jlog.NewJournal(loglevel)
	} else {
		log.Current = log.StdLogger{Level: loglevel}
	}

	// Inform the user which (if any) config file was used.
	if cfg.Files.Config != "" {
		log.Infof("Using config file: %s", cfg.Files.Config)
	} else {
		log.Warn("No config file was found. Resorting to defaults")
	}

	// Setup complete, time to do some work
	if flag.Client {
		mixprep()
	} else if flag.Stdin {
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
	} else if flag.Remailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else if flag.Dummy {
		injectDummy()
	} else if flag.Refresh {
		fmt.Printf("Keyring refresh: from=%s, to=%s\n", cfg.Urls.Pubring, cfg.Files.Pubring)
		httpGet(cfg.Urls.Pubring, cfg.Files.Pubring)
		fmt.Printf("Stats refresh: from=%s, to=%s\n", cfg.Urls.Mlist2, cfg.Files.Mlist2)
		httpGet(cfg.Urls.Mlist2, cfg.Files.Mlist2)
	}
	if flag.Send {
		// Flush the outbound pool
		poolOutboundSend()
	}
}
