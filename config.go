package main

import (
	"fmt"
	"os"
	"flag"
	"path"
	"path/filepath"
	"code.google.com/p/gcfg"
)

type Config struct {
	Files struct {
		Pubring string
		Mlist2 string
		Pubkey string
		Secring string
		Adminkey string
		Help string
		Pooldir string
		Maildir string
		IDlog string
	}
	Mail struct {
		Sendmail bool
		Outfile bool
		SMTPRelay string
		SMTPPort int
		EnvelopeSender string
		SMTPUsername string
		SMTPPassword string
	}
	Stats struct {
		Minlat int
		Maxlat int
		Minrel float32
		Relfinal float32
		Numcopies int
		Distance int
		StaleHrs int
	}
	Pool struct {
		Size int
		Rate int
		Loop int
	}
	Remailer struct {
		Name string
		Address string
		Exit bool
		MaxSize int
		IDexp int
		Loglevel string
		Daemon bool
	}
}

func init() {
	var err error
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
	flag.StringVar(&flag_chain, "chain", "*,*,*", "Remailer chain")
	flag.StringVar(&flag_chain, "l", "*,*,*", "Remailer chain")
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
	// Memory usage
	flag.BoolVar(&flag_meminfo, "meminfo", false, "Print memory info")

	// Figure out the dir of the yamn binary
	var dir string
	dir, err = filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}

	// Set defaults and read config file
	cfg.Files.Pubkey = path.Join(dir, "key.txt")
	cfg.Files.Pubring = path.Join(dir, "pubring.mix")
	cfg.Files.Secring = path.Join(dir, "secring.mix")
	cfg.Files.Mlist2 = path.Join(dir, "mlist2.txt")
	cfg.Files.Adminkey = path.Join(dir, "adminkey.txt")
	cfg.Files.Help = path.Join(dir, "help.txt")
	cfg.Files.Pooldir = path.Join(dir, "pool")
	cfg.Files.Maildir = path.Join(dir, "Maildir")
	cfg.Files.IDlog = path.Join(dir, "idlog")
	cfg.Mail.Sendmail = true
	cfg.Mail.Outfile = false
	cfg.Mail.SMTPRelay = "127.0.0.1"
	cfg.Mail.SMTPPort = 25
	cfg.Mail.EnvelopeSender = "nobody@nowhere.invalid"
	cfg.Mail.SMTPUsername = ""
	cfg.Mail.SMTPPassword = ""
	cfg.Stats.Minrel = 98.0
	cfg.Stats.Relfinal = 99.0
	cfg.Stats.Minlat = 2
	cfg.Stats.Maxlat = 60
	cfg.Stats.Numcopies = 1
	cfg.Stats.Distance = 2
	cfg.Stats.StaleHrs = 24
	cfg.Pool.Size = 45
	cfg.Pool.Rate = 65
	cfg.Pool.Loop = 300
	cfg.Remailer.Name = "anon"
	cfg.Remailer.Address = "mix@nowhere.invalid"
	cfg.Remailer.Exit = false
	cfg.Remailer.MaxSize = 12
	cfg.Remailer.IDexp = 14
	cfg.Remailer.Loglevel = "info"
	cfg.Remailer.Daemon = false

	if flag_config != "" {
		err = gcfg.ReadFileInto(&cfg, flag_config)
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flag_config)
			os.Exit(1)
		}
	} else if os.Getenv("GOLANG") != "" {
		err = gcfg.ReadFileInto(&cfg, os.Getenv("GOLANG"))
		if err != nil {
			fmt.Fprintf(
				os.Stderr, "Unable to read %s\n", flag_config)
			os.Exit(1)
		}
	} else {
		fn := path.Join(dir, "yamn.cfg")
		err = gcfg.ReadFileInto(&cfg, fn)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Unable to read %s: %s\n", fn, err)
			os.Exit(1)
		}
	}
}

func flags() {
	flag.Parse()
	flag_args = flag.Args()
}

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
