package main

import (
	"flag"
	"fmt"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/gcfg.v1"
	"os"
	"path"
)

type Config struct {
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
		Loglevel    string
		Daemon      bool
	}
}

func init() {
	// Function as a client
	flag.BoolVar(&flag_client, "mail", false, "Function as a client")
	flag.BoolVar(&flag_client, "m", false, "Function as a client")
	// Send (from pool)
	flag.BoolVar(&flag_send, "send", false, "Force pool send")
	flag.BoolVar(&flag_send, "S", false, "Force pool send")
	// Perform remailer actions
	flag.BoolVar(&flag_remailer, "remailer", false,
		"Perform routine remailer actions")
	flag.BoolVar(&flag_remailer, "M", false,
		"Perform routine remailer actions")
	// Start remailer as a daemon
	flag.BoolVar(&flag_daemon, "daemon", false,
		"Start remailer as a daemon. (Requires -M")
	flag.BoolVar(&flag_daemon, "D", false,
		"Start remailer as a daemon. (Requires -M")
	// Remailer chain
	flag.StringVar(&flag_chain, "chain", "", "Remailer chain")
	flag.StringVar(&flag_chain, "l", "", "Remailer chain")
	// Recipient address
	flag.StringVar(&flag_to, "to", "", "Recipient email address")
	flag.StringVar(&flag_to, "t", "", "Recipient email address")
	// Subject header
	flag.StringVar(&flag_subject, "subject", "", "Subject header")
	flag.StringVar(&flag_subject, "s", "", "Subject header")
	// Number of copies
	flag.IntVar(&flag_copies, "copies", 0, "Number of copies")
	flag.IntVar(&flag_copies, "c", 0, "Number of copies")
	// Config file
	flag.StringVar(&flag_config, "config", "", "Config file")
	// Read STDIN
	flag.BoolVar(&flag_stdin, "read-mail", false, "Read a message from stdin")
	flag.BoolVar(&flag_stdin, "R", false, "Read a message from stdin")
	// Write to STDOUT
	flag.BoolVar(&flag_stdout, "stdout", false, "Write message to stdout")
	// Inject dummy
	flag.BoolVar(&flag_dummy, "dummy", false, "Inject a dummy message")
	flag.BoolVar(&flag_dummy, "d", false, "Inject a dummy message")
	// Disable dummy messaging
	flag.BoolVar(&flag_nodummy, "nodummy", false, "Don't send dummies")
	// Print Version
	flag.BoolVar(&flag_version, "version", false, "Print version string")
	flag.BoolVar(&flag_version, "V", false, "Print version string")
	// Print debug info
	flag.BoolVar(&flag_debug, "debug", false, "Print detailed config")
	// Memory usage
	flag.BoolVar(&flag_meminfo, "meminfo", false, "Print memory info")

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
	flag.StringVar(&flag_basedir, "dir", cfgDir, "Base directory")
}

func setDefaultConfig() {
	// Set defaults and read config file
	cfg.Files.Pubkey = path.Join(flag_basedir, "key.txt")
	cfg.Files.Pubring = path.Join(flag_basedir, "pubring.mix")
	cfg.Files.Secring = path.Join(flag_basedir, "secring.mix")
	cfg.Files.Mlist2 = path.Join(flag_basedir, "mlist2.txt")
	cfg.Files.Adminkey = path.Join(flag_basedir, "adminkey.txt")
	cfg.Files.Help = path.Join(flag_basedir, "help.txt")
	cfg.Files.Pooldir = path.Join(flag_basedir, "pool")
	cfg.Files.Maildir = path.Join(flag_basedir, "Maildir")
	cfg.Files.IDlog = path.Join(flag_basedir, "idlog")
	cfg.Files.ChunkDB = path.Join(flag_basedir, "chunkdb")
	cfg.Urls.Fetch = true
	cfg.Urls.Pubring = "http://www.mixmin.net/yamn/pubring.mix"
	cfg.Urls.Mlist2 = "http://www.mixmin.net/yamn/mlist2.txt"
	cfg.Mail.Sendmail = false
	cfg.Mail.Outfile = false
	cfg.Mail.SMTPRelay = "fleegle.mixmin.net"
	cfg.Mail.SMTPPort = 587
	cfg.Mail.UseTLS = true
	cfg.Mail.MXRelay = true
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
	cfg.Stats.Chain = "yamn4,*,*"
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
	cfg.Remailer.Loglevel = "info"
	cfg.Remailer.Daemon = false
}

// abort is a shortcut for print an error message and exit
func abort(reason string) {
	fmt.Fprintln(os.Stderr, reason)
	os.Exit(1)
}

// validateThresholds tests config against some sane thresholds
func validateThresholds() {
	if flag_remailer {
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
	flag_args = flag.Args()
	setDefaultConfig()
	if flag_config != "" {
		err = gcfg.ReadFileInto(&cfg, flag_config)
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flag_config)
			os.Exit(1)
		}
	} else if os.Getenv("YAMNCFG") != "" {
		err = gcfg.ReadFileInto(&cfg, os.Getenv("YAMNCFG"))
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flag_config)
			os.Exit(1)
		}
	} else {
		fn := path.Join(flag_basedir, "yamn.cfg")
		err = gcfg.ReadFileInto(&cfg, fn)
		if err != nil {
			if !flag_client {
				fmt.Println(err)
			}
			fmt.Println("Using internal, default config.")
		}
	}
	if flag_version {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if flag_debug {
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Basedir: %s\n", flag_basedir)
		if os.Getenv("YAMNCFG") != "" {
			fmt.Printf("YAMNCFG: %s\n", os.Getenv("YAMNCFG"))
		}
		if os.Getenv("YAMNDIR") != "" {
			fmt.Printf("YAMNDIR: %s\n", os.Getenv("YAMNDIR"))
		}
		if cfg.Stats.UseExpired {
			fmt.Println("Configured to use Expired Keys")
		}
		fmt.Printf("\nMaximum chain length: %d\n", maxChainLength)
		fmt.Printf("Per header bytes: %d\n", headerBytes)
		fmt.Printf("Total header bytes: %d\n", headersBytes)
		fmt.Printf("Payload bytes: %d\n", bodyBytes)
		fmt.Printf("Message bytes: %d\n", messageBytes)
		os.Exit(0)
	}
	validateThresholds()
}

var flag_basedir string
var flag_debug bool
var flag_client bool
var flag_send bool
var flag_remailer bool
var flag_daemon bool
var flag_chain string
var flag_to string
var flag_subject string
var flag_args []string
var flag_config string
var flag_copies int
var flag_stdin bool
var flag_stdout bool
var flag_dummy bool
var flag_nodummy bool
var flag_version bool
var flag_meminfo bool
var cfg Config
