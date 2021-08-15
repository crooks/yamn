package config

import (
	"flag"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
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

type Flags struct {
	Debug    bool
	Client   bool
	Send     bool
	Refresh  bool
	Remailer bool
	Daemon   bool
	Chain    string
	To       string
	Subject  string
	Args     []string
	Config   string
	Copies   int
	Stdin    bool
	Stdout   bool
	Dummy    bool
	NoDummy  bool
	Version  bool
	MemInfo  bool
}

func (c *Config) WriteConfig(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ParseFlags() *Flags {
	f := new(Flags)
	// Function as a client
	flag.BoolVar(&f.Client, "mail", false, "Function as a client")
	flag.BoolVar(&f.Client, "m", false, "Function as a client")
	// Send (from pool)
	flag.BoolVar(&f.Send, "send", false, "Force pool send")
	flag.BoolVar(&f.Send, "S", false, "Force pool send")
	// Perform remailer actions
	flag.BoolVar(&f.Remailer, "remailer", false,
		"Perform routine remailer actions")
	flag.BoolVar(&f.Remailer, "M", false,
		"Perform routine remailer actions")
	// Start remailer as a daemon
	flag.BoolVar(&f.Daemon, "daemon", false,
		"Start remailer as a daemon. (Requires -M")
	flag.BoolVar(&f.Daemon, "D", false,
		"Start remailer as a daemon. (Requires -M")
	// Remailer chain
	flag.StringVar(&f.Chain, "chain", "", "Remailer chain")
	flag.StringVar(&f.Chain, "l", "", "Remailer chain")
	// Recipient address
	flag.StringVar(&f.To, "to", "", "Recipient email address")
	flag.StringVar(&f.To, "t", "", "Recipient email address")
	// Subject header
	flag.StringVar(&f.Subject, "subject", "", "Subject header")
	flag.StringVar(&f.Subject, "s", "", "Subject header")
	// Number of copies
	flag.IntVar(&f.Copies, "copies", 0, "Number of copies")
	flag.IntVar(&f.Copies, "c", 0, "Number of copies")
	// Config file
	flag.StringVar(&f.Config, "config", "", "Config file")
	// Read STDIN
	flag.BoolVar(&f.Stdin, "read-mail", false, "Read a message from stdin")
	flag.BoolVar(&f.Stdin, "R", false, "Read a message from stdin")
	// Write to STDOUT
	flag.BoolVar(&f.Stdout, "stdout", false, "Write message to stdout")
	// Inject dummy
	flag.BoolVar(&f.Dummy, "dummy", false, "Inject a dummy message")
	flag.BoolVar(&f.Dummy, "d", false, "Inject a dummy message")
	// Disable dummy messaging
	flag.BoolVar(&f.NoDummy, "nodummy", false, "Don't send dummies")
	// Print Version
	flag.BoolVar(&f.Version, "version", false, "Print version string")
	flag.BoolVar(&f.Version, "V", false, "Print version string")
	// Print debug info
	flag.BoolVar(&f.Debug, "debug", false, "Print detailed config")
	// Memory usage
	flag.BoolVar(&f.MemInfo, "meminfo", false, "Print memory info")
	// Refresh remailer stats files
	flag.BoolVar(&f.Refresh, "refresh", false, "Refresh remailer stats files")

	flag.Parse()

	// If a "--config" flag hasn't been provided, try reading a YAMNCFG environment variable.
	if f.Config == "" && os.Getenv("YAMNCFG") != "" {
		f.Config = os.Getenv("YAMNCFG")
	}
	return f
}

func ParseConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	y := yaml.NewDecoder(file)
	config := new(Config)
	if err := y.Decode(&config); err != nil {
		return nil, err
	}
	return config, nil
}
