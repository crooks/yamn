package config

import (
	"flag"
	"io/ioutil"
	"os"
	"path"

	"gopkg.in/yaml.v2"
)

// Config contains all the configuration settings for Yamn.
type Config struct {
	General struct {
		Loglevel  string `yaml:"loglevel"`
		LogToFile bool   `yaml:"logtofile"`
	} `yaml:"general"`
	Files struct {
		Pubring  string `yaml:"pubring"`
		Mlist2   string `yaml:"mlist2"`
		Pubkey   string `yaml:"pubkey"`
		Secring  string `yaml:"secring"`
		Adminkey string `yaml:"adminkey"`
		Help     string `yaml:"help"`
		Pooldir  string `yaml:"pooldir"`
		Maildir  string `yaml:"maildir"`
		IDlog    string `yaml:"idlog"`
		ChunkDB  string `yaml:"chunkdb"`
		Logfile  string `yaml:"logfile"`
	} `yaml:"files"`
	Urls struct {
		Fetch   bool   `yaml:"fetch"`
		Pubring string `yaml:"pubring"`
		Mlist2  string `yaml:"mlist2"`
	} `yaml:"urls"`
	Mail struct {
		Sendmail     bool   `yaml:"sendmail"`
		Pipe         string `yaml:"pipe"`
		Outfile      bool   `yaml:"outfile"`
		UseTLS       bool   `yaml:"usetls"`
		SMTPRelay    string `yaml:"smtp_relay"`
		SMTPPort     int    `yaml:"smtp_port"`
		MXRelay      bool   `yaml:"mx_relay"`
		OnionRelay   bool   `yaml:"onion_relay"`
		Sender       string `yaml:"sender"`
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
		OutboundName string `yaml:"outbound_name"`
		OutboundAddy string `yaml:"outbound_addy"`
		CustomFrom   bool   `yaml:"custom_from"`
	} `yaml:"mail"`
	Stats struct {
		Minlat     int     `yaml:"minlat"`
		Maxlat     int     `yaml:"maxlat"`
		Minrel     float32 `yaml:"minrel"`
		Relfinal   float32 `yaml:"rel_final"`
		Chain      string  `yaml:"chain"`
		Numcopies  int     `yaml:"num_copies"`
		Distance   int     `yaml:"distance"`
		StaleHrs   int     `yaml:"stale_hours"`
		UseExpired bool    `yaml:"use_expired"`
	} `yaml:"stats"`
	Pool struct {
		Size    int `yaml:"size"`
		Rate    int `yaml:"rate"`
		MinSend int `yaml:"min_send"`
		Loop    int `yaml:"loop"`
		// Delete excessively old messages from the outbound pool
		MaxAge int `yaml:"max_age"`
	} `yaml:"pool"`
	Remailer struct {
		Name        string `yaml:"name"`
		Address     string `yaml:"address"`
		Exit        bool   `yaml:"exit"`
		MaxSize     int    `yaml:"max_size"`
		IDexp       int    `yaml:"id_expire"`
		ChunkExpire int    `yaml:"chunk_expire"`
		MaxAge      int    `yaml:"max_age"`
		Keylife     int    `yaml:"key_life"`
		Keygrace    int    `yaml:"key_grace"`
		Daemon      bool   `yaml:"daemon"`
	} `yaml:"remailer"`
}

type Flags struct {
	Dir      string
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
	// Base DIR for easy setting of some default file paths
	flag.StringVar(&f.Dir, "dir", "", "Base DIR for YAMN files")
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

// newConfig returns a new instance of Config with some predefined defaults
func (flags *Flags) newConfig() *Config {
	cfg := new(Config)
	// Default values defined here will be overridden by unmarshaling a config file
	cfg.General.Loglevel = "warn"
	cfg.General.LogToFile = false // By default, log to stdout/stderr
	// Config items in the Files section default to a path defined by the --dir flag
	cfg.Files.Pubkey = path.Join(flags.Dir, "key.txt")
	cfg.Files.Pubring = path.Join(flags.Dir, "pubring.mix")
	cfg.Files.Secring = path.Join(flags.Dir, "secring.mix")
	cfg.Files.Mlist2 = path.Join(flags.Dir, "mlist2.txt")
	cfg.Files.Adminkey = path.Join(flags.Dir, "adminkey.txt")
	cfg.Files.Help = path.Join(flags.Dir, "help.txt")
	cfg.Files.Pooldir = path.Join(flags.Dir, "pool")
	cfg.Files.Maildir = path.Join(flags.Dir, "Maildir")
	cfg.Files.IDlog = path.Join(flags.Dir, "idlog")
	cfg.Files.ChunkDB = path.Join(flags.Dir, "chunkdb")
	cfg.Files.Logfile = path.Join(flags.Dir, "yamn.log")
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
	return cfg
}

// ParseConfig returns an instance of Config with defaults overridden by the content of a config file
func (flags *Flags) ParseConfig() (*Config, error) {
	// Fetch an instance of Config with defaults predefined
	c := flags.newConfig()
	// Read a YAML config file
	yamlBytes, err := os.ReadFile(flags.Config)
	if err != nil {
		return nil, err
	}
	// Unmarshal the content of the YAML config file over the existing struct instance
	err = yaml.Unmarshal(yamlBytes, &c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
