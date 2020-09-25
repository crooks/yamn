package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/gcfg.v1"
)

// Config contains all the configuration settings for Yamn.
type Config struct {
	General struct {
		Loglevel  string
		LogToFile bool
	}
	Files struct {
		Pubring  string
		Mlist2   string
		Pubkey   string
		Secring  string
		Adminkey string
		Help     string
		Pooldir  string
		Maildir  string
		IDlog    string
		ChunkDB  string
		Logfile  string
	}
	Urls struct {
		Fetch   bool
		Pubring string
		Mlist2  string
	}
	Mail struct {
		Sendmail     bool
		Pipe         string
		Outfile      bool
		UseTLS       bool
		SMTPRelay    string
		SMTPPort     int
		MXRelay      bool
		OnionRelay   bool
		Sender       string
		Username     string
		Password     string
		OutboundName string
		OutboundAddy string
		CustomFrom   bool
	}
	Stats struct {
		Minlat     int
		Maxlat     int
		Minrel     float32
		Relfinal   float32
		Chain      string
		Numcopies  int
		Distance   int
		StaleHrs   int
		UseExpired bool
	}
	Pool struct {
		Size    int
		Rate    int
		MinSend int
		Loop    int
		// Delete excessively old messages from the outbound pool
		MaxAge int
	}
	Remailer struct {
		Name        string
		Address     string
		Exit        bool
		MaxSize     int
		IDexp       int
		ChunkExpire int
		MaxAge      int
		Keylife     int
		Keygrace    int
		Daemon      bool
	}
}

func init() {
	// Function as a client
	flag.BoolVar(&flagClient, "mail", false, "Function as a client")
	flag.BoolVar(&flagClient, "m", false, "Function as a client")
	// Send (from pool)
	flag.BoolVar(&flagSend, "send", false, "Force pool send")
	flag.BoolVar(&flagSend, "S", false, "Force pool send")
	// Perform remailer actions
	flag.BoolVar(&flagRemailer, "remailer", false,
		"Perform routine remailer actions")
	flag.BoolVar(&flagRemailer, "M", false,
		"Perform routine remailer actions")
	// Start remailer as a daemon
	flag.BoolVar(&flagDaemon, "daemon", false,
		"Start remailer as a daemon. (Requires -M")
	flag.BoolVar(&flagDaemon, "D", false,
		"Start remailer as a daemon. (Requires -M")
	// Remailer chain
	flag.StringVar(&flagChain, "chain", "", "Remailer chain")
	flag.StringVar(&flagChain, "l", "", "Remailer chain")
	// Recipient address
	flag.StringVar(&flagTo, "to", "", "Recipient email address")
	flag.StringVar(&flagTo, "t", "", "Recipient email address")
	// Subject header
	flag.StringVar(&flagSubject, "subject", "", "Subject header")
	flag.StringVar(&flagSubject, "s", "", "Subject header")
	// Number of copies
	flag.IntVar(&flagCopies, "copies", 0, "Number of copies")
	flag.IntVar(&flagCopies, "c", 0, "Number of copies")
	// Config file
	flag.StringVar(&flagConfig, "config", "", "Config file")
	// Read STDIN
	flag.BoolVar(&flagStdin, "read-mail", false, "Read a message from stdin")
	flag.BoolVar(&flagStdin, "R", false, "Read a message from stdin")
	// Write to STDOUT
	flag.BoolVar(&flagStdout, "stdout", false, "Write message to stdout")
	// Inject dummy
	flag.BoolVar(&flagDummy, "dummy", false, "Inject a dummy message")
	flag.BoolVar(&flagDummy, "d", false, "Inject a dummy message")
	// Disable dummy messaging
	flag.BoolVar(&flagNoDummy, "nodummy", false, "Don't send dummies")
	// Print Version
	flag.BoolVar(&flagVersion, "version", false, "Print version string")
	flag.BoolVar(&flagVersion, "V", false, "Print version string")
	// Print debug info
	flag.BoolVar(&flagDebug, "debug", false, "Print detailed config")
	// Memory usage
	flag.BoolVar(&flagMemInfo, "meminfo", false, "Print memory info")

	// Define our base working directory
	var cfgDir string
	var useThisDir bool
	if os.Getenv("YAMNDIR") != "" {
		// Use this Dir without further testing, just because we're
		// explicitly intstructed to do so.
		cfgDir = os.Getenv("YAMNDIR")
		useThisDir = true
	} else {
		// Test for a yamn.cfg in the Present Working Directory
		useThisDir, cfgDir = cfgInPwd()
		// Test for $HOME/yamn/yamn.cfg
		if !useThisDir {
			useThisDir, cfgDir = cfgInHome()
		}
		// Test for /etc/yamn/yamn.cfg
		if !useThisDir {
			cfgDir = "/etc/yamn"
			useThisDir = cfgInDir(cfgDir)
		}
	}
	if !useThisDir {
		fmt.Println(
			"Unable to determine Yamn's basedir. ",
			"Continuing with a slight sense of trepidation.",
		)
	}
	flag.StringVar(&flagBasedir, "dir", cfgDir, "Base directory")
}

func setDefaultConfig() {
	// Set defaults and read config file
	cfg.General.Loglevel = "warn"
	cfg.General.LogToFile = false // By default, log to stdout/stderr
	cfg.Files.Pubkey = path.Join(flagBasedir, "key.txt")
	cfg.Files.Pubring = path.Join(flagBasedir, "pubring.mix")
	cfg.Files.Secring = path.Join(flagBasedir, "secring.mix")
	cfg.Files.Mlist2 = path.Join(flagBasedir, "mlist2.txt")
	cfg.Files.Adminkey = path.Join(flagBasedir, "adminkey.txt")
	cfg.Files.Help = path.Join(flagBasedir, "help.txt")
	cfg.Files.Pooldir = path.Join(flagBasedir, "pool")
	cfg.Files.Maildir = path.Join(flagBasedir, "Maildir")
	cfg.Files.IDlog = path.Join(flagBasedir, "idlog")
	cfg.Files.ChunkDB = path.Join(flagBasedir, "chunkdb")
	cfg.Files.Logfile = path.Join(flagBasedir, "yamn.log")
	cfg.Urls.Fetch = true
	cfg.Urls.Pubring = "http://www.mixmin.net/yamn/pubring.mix"
	cfg.Urls.Mlist2 = "http://www.mixmin.net/yamn/mlist2.txt"
	cfg.Mail.Sendmail = false
	cfg.Mail.Outfile = false
	cfg.Mail.SMTPRelay = "fleegle.mixmin.net"
	cfg.Mail.SMTPPort = 587
	cfg.Mail.UseTLS = true
	cfg.Mail.MXRelay = true
	cfg.Mail.OnionRelay = false // Allow .onion addresses as MX relays
	cfg.Mail.Sender = ""
	cfg.Mail.Username = ""
	cfg.Mail.Password = ""
	cfg.Mail.OutboundName = "Anonymous Remailer"
	cfg.Mail.OutboundAddy = "remailer@domain.invalid"
	cfg.Mail.CustomFrom = false
	cfg.Stats.Minrel = 98.0
	cfg.Stats.Relfinal = 99.0
	cfg.Stats.Minlat = 2
	cfg.Stats.Maxlat = 60
	cfg.Stats.Chain = "*,*,*"
	cfg.Stats.Numcopies = 1
	cfg.Stats.Distance = 2
	cfg.Stats.StaleHrs = 24
	cfg.Stats.UseExpired = false
	cfg.Pool.Size = 5 // Good for startups, too small for established
	cfg.Pool.Rate = 65
	cfg.Pool.MinSend = 5 // Only used in Binomial Mix Pools
	cfg.Pool.Loop = 300
	cfg.Pool.MaxAge = 28
	cfg.Remailer.Name = "anon"
	cfg.Remailer.Address = "mix@nowhere.invalid"
	cfg.Remailer.Exit = false
	cfg.Remailer.MaxSize = 12
	cfg.Remailer.IDexp = 14
	cfg.Remailer.ChunkExpire = 60
	// Discard messages if packet timestamp exceeds this age in days
	cfg.Remailer.MaxAge = 14
	cfg.Remailer.Keylife = 14
	cfg.Remailer.Keygrace = 28
	cfg.Remailer.Daemon = false
}

// abort is a shortcut for print an error message and exit
func abort(reason string) {
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(1)
}

// validateThresholds tests config against some sane thresholds
func validateThresholds() {
	if flagRemailer {
		if cfg.Remailer.Keylife < 5 {
			msg := fmt.Sprintf(
				"Key life of %d is too short. "+
					"Must be at least 5 days.",
				cfg.Remailer.Keylife,
			)
			abort(msg)
		}
		if cfg.Remailer.Keygrace < 5 {
			msg := fmt.Sprintf(
				"Key grace of %d is too short. "+
					"Must be at least 5 days.",
				cfg.Remailer.Keygrace,
			)
			abort(msg)
		}
	}
}

// cfgInHome tries to ascertain the user's homedir and then tests if there's
// a subdir of /yamn/ with a yamn.cfg file in it.
func cfgInHome() (goodCfg bool, cfgDir string) {
	home, err := homedir.Dir()
	if err != nil {
		// TODO log message
		return
	}
	cfgDir = path.Join(home, "yamn")
	goodCfg, err = isPath(path.Join(cfgDir, "yamn.cfg"))
	if err != nil {
		// TODO log message
		goodCfg = false
		return
	}
	return
}

// cfgInPwd figures out the present working directory and tests if yamn.cfg is
// in it.
func cfgInPwd() (goodCfg bool, pwdcfg string) {
	pwdcfg, err := os.Getwd()
	if err != nil {
		//TODO log message
		return
	}
	goodCfg, err = isPath(path.Join(pwdcfg, "yamn.cfg"))
	if err != nil {
		//TODO log message
		goodCfg = false
		return
	}
	return
}

// cfgInDir tests for the existence of a yamn.cfg file in a given directory.
func cfgInDir(cfgDir string) bool {
	exists, err := isPath(path.Join(cfgDir, "yamn.cfg"))
	if err != nil {
		//TODO log message
		return false
	}
	return exists
}

func flags() {
	var err error
	flag.Parse()
	flagArgs = flag.Args()
	setDefaultConfig()
	if flagConfig != "" {
		err = gcfg.ReadFileInto(&cfg, flagConfig)
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flagConfig)
			os.Exit(1)
		}
	} else if os.Getenv("YAMNCFG") != "" {
		err = gcfg.ReadFileInto(&cfg, os.Getenv("YAMNCFG"))
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flagConfig)
			os.Exit(1)
		}
	} else {
		fn := path.Join(flagBasedir, "yamn.cfg")
		err = gcfg.ReadFileInto(&cfg, fn)
		if err != nil {
			fmt.Printf("Error: Unable to read config: %s", err)
			os.Exit(1)
		}
	}
	if flagVersion {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	validateThresholds()
}

var flagBasedir string
var flagDebug bool
var flagClient bool
var flagSend bool
var flagRemailer bool
var flagDaemon bool
var flagChain string
var flagTo string
var flagSubject string
var flagArgs []string
var flagConfig string
var flagCopies int
var flagStdin bool
var flagStdout bool
var flagDummy bool
var flagNoDummy bool
var flagVersion bool
var flagMemInfo bool
var cfg Config
