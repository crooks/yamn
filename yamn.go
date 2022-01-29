package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Masterminds/log-go"
	"github.com/crooks/yamn/config"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

const (
	version        string = "0.2.5"
	dayLength      int    = 24 * 60 * 60 // Day in seconds
	maxFragLength         = 17910
	maxCopies             = 5
	base64LineWrap        = 64
	rfc5322date           = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortdate             = "2 Jan 2006"
)

var (
	// flags - Command line flags
	flags *config.Flags
	// cfg - Config parameters
	cfg *config.Config
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

func main() {
	var err error
	flags = config.ParseFlags()
	if flags.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	// Some config defaults are derived from flags so ParseConfig is a flags method
	cfg, err = flags.ParseConfig()
	if err != nil {
		// No logging is defined at this point so log the error to stderr
		fmt.Fprintf(os.Stderr, "Unable to parse config file: %v", err)
		os.Exit(1)
	}
	// If the debug flag is set, print the config and exit
	if flags.Debug {
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
	log.Current = log.StdLogger{Level: loglevel}

	// Inform the user which (if any) config file was used.
	if cfg.Files.Config != "" {
		log.Infof("Using config file: %s", cfg.Files.Config)
	} else {
		log.Warn("No config file was found. Resorting to defaults")
	}

	// Setup complete, time to do some work
	if flags.Client {
		mixprep()
	} else if flags.Stdin {
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
	} else if flags.Remailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else if flags.Dummy {
		injectDummy()
	} else if flags.Refresh {
		fmt.Printf("Keyring refresh: from=%s, to=%s\n", cfg.Urls.Pubring, cfg.Files.Pubring)
		httpGet(cfg.Urls.Pubring, cfg.Files.Pubring)
		fmt.Printf("Stats refresh: from=%s, to=%s\n", cfg.Urls.Mlist2, cfg.Files.Mlist2)
		httpGet(cfg.Urls.Mlist2, cfg.Files.Mlist2)
	}
	if flags.Send {
		// Flush the outbound pool
		poolOutboundSend()
	}
}
