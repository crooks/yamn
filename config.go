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
		Pooldir string
		Maildir string
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
	}
	Pool struct {
		Size int
		Rate int
	}
	Remailer struct {
		Name string
		Address string
		Exit bool
		MaxSize int
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
	// Print Version
	flag.BoolVar(&flag_version, "version", false, "Print version string")
	flag.BoolVar(&flag_version, "V", false, "Print version string")
	// Memory usage
	flag.BoolVar(&flag_meminfo, "meminfo", false, "Print memory info")

	// Set defaults and read config file
	cfg.Files.Pubkey = "key.txt"
	cfg.Files.Pubring = "pubring.mix"
	cfg.Files.Secring = "secring.mix"
	cfg.Files.Mlist2 = "mlist2.txt"
	cfg.Files.Pooldir = "pool"
	cfg.Files.Maildir = "Maildir"
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
	cfg.Pool.Size = 45
	cfg.Pool.Rate = 65
	cfg.Remailer.Name = "anon"
	cfg.Remailer.Address = "mix@nowhere.invalid"
	cfg.Remailer.Exit = false
	cfg.Remailer.MaxSize = 12

	if flag_config != "" {
		err = gcfg.ReadFileInto(&cfg, flag_config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read %s", flag_config)
			os.Exit(1)
		}
	} else if os.Getenv("GOLANG") != "" {
		err = gcfg.ReadFileInto(&cfg, os.Getenv("GOLANG"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read %s", flag_config)
			os.Exit(1)
		}
	} else {
		var dir string
		dir, err = filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			panic(err)
		}
		fn := path.Join(dir, "yamn.cfg")
		err = gcfg.ReadFileInto(&cfg, fn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read %s - %s", fn, err)
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
var flag_chain string
var flag_to string
var flag_subject string
var flag_args []string
var flag_config string
var flag_copies int
var flag_stdin bool
var flag_stdout bool
var flag_version bool
var flag_meminfo bool
var cfg Config
