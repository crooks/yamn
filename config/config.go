package config

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

// Config contains all the configuration settings for Yamn.
type Config struct {
	General struct {
		Loglevel     string `yaml:"loglevel"`
		LogToFile    bool   `yaml:"logtofile"`
		LogToJournal bool   `yaml:"logtojournal"`
	} `yaml:"general"`
	Files struct {
		// Config is a special variable that returns the name of the active config file.
		// If it's set in the config file, it will be ignored.
		Config   string
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

// GetCfg parses the command line flags and config file if they haven't been previously parsed.
// This should be an init function but tests fail if flags are parsed in init.
//  See: https://github.com/golang/go/issues/46869
func GetCfg() (*Flags, *Config) {
	var err error
	f := ParseFlags()
	// Some config defaults are derived from flags so ParseConfig is a flags method
	c, err := f.ParseConfig()
	if err != nil {
		// No logging is defined at this point so log the error to stderr
		fmt.Fprintf(os.Stderr, "Unable to parse config file: %v", err)
		os.Exit(1)
	}
	return f, c
}

// WriteConfig will write the current config to a given filename
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

func (c *Config) Debug() ([]byte, error) {
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	return data, err
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
	flag.BoolVar(&f.Remailer, "remailer", false, "Perform routine remailer actions")
	flag.BoolVar(&f.Remailer, "M", false, "Perform routine remailer actions")
	// Start remailer as a daemon
	flag.BoolVar(&f.Daemon, "daemon", false, "Start remailer as a daemon. (Requires -M)")
	flag.BoolVar(&f.Daemon, "D", false, "Start remailer as a daemon. (Requires -M)")
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
	flag.IntVar(&f.Copies, "copies", 2, "Number of copies")
	flag.IntVar(&f.Copies, "c", 2, "Number of copies")
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
	return f
}

// findConfig attempts to locate a yamn config file
func (f *Flags) findConfig() (string, error) {
	var err error
	var cfgFile string
	// if a --config flag was passed, try that as the highest priority
	if _, err = os.Stat(f.Config); err == nil {
		return f.Config, nil
	}
	// Does the environment variable YAMNCFG point to a valid file?
	if _, err = os.Stat(os.Getenv("YAMNCFG")); err == nil {
		return os.Getenv("YAMNCFG"), nil
	}
	// Is there a yamn.yml in the PWD?
	pwd, err := os.Getwd()
	if err == nil {
		cfgFile = path.Join(pwd, "yamn.yml")
		if _, err = os.Stat(cfgFile); err == nil {
			return cfgFile, nil
		}
	}
	// Is there a yamn.yml file in the dir flag directory
	cfgFile = path.Join(f.Dir, "yamn.yml")
	if _, err = os.Stat(cfgFile); err == nil {
		return cfgFile, nil
	}
	// Look for a yamn.yml in the user's homedir
	home, err := os.UserHomeDir()
	if err == nil {
		cfgFile = path.Join(home, "yamn.yml")
		if _, err = os.Stat(cfgFile); err == nil {
			return cfgFile, nil
		}
	}
	// Last gasp: Try /etc/yamn.yml.
	cfgFile = "/etc/yamn.yml"
	if _, err = os.Stat(cfgFile); err == nil {
		return cfgFile, nil
	}
	// Return an error to indicate no config file has been found
	return "", os.ErrNotExist
}

// newConfig returns a new instance of Config with some predefined defaults
func (f *Flags) newConfig() *Config {
	c := new(Config)
	// Default values defined here will be overridden by unmarshaling a config file
	c.General.Loglevel = "warn"
	c.General.LogToFile = false    // By default, log to stdout/stderr
	c.General.LogToJournal = false // Don't log to journal by default
	// Config items in the Files section default to a path defined by the --dir flag
	c.Files.Pubkey = path.Join(f.Dir, "key.txt")
	c.Files.Pubring = path.Join(f.Dir, "pubring.mix")
	c.Files.Secring = path.Join(f.Dir, "secring.mix")
	c.Files.Mlist2 = path.Join(f.Dir, "mlist2.txt")
	c.Files.Adminkey = path.Join(f.Dir, "adminkey.txt")
	c.Files.Help = path.Join(f.Dir, "help.txt")
	c.Files.Pooldir = path.Join(f.Dir, "pool")
	c.Files.Maildir = path.Join(f.Dir, "Maildir")
	c.Files.IDlog = path.Join(f.Dir, "idlog")
	c.Files.ChunkDB = path.Join(f.Dir, "chunkdb")
	c.Files.Logfile = path.Join(f.Dir, "yamn.log")
	c.Urls.Fetch = true
	c.Urls.Pubring = "http://www.mixmin.net/yamn/pubring.mix"
	c.Urls.Mlist2 = "http://www.mixmin.net/yamn/mlist2.txt"
	c.Mail.Sendmail = false
	c.Mail.Outfile = false
	c.Mail.SMTPRelay = "fleegle.mixmin.net"
	c.Mail.SMTPPort = 587
	c.Mail.UseTLS = true
	c.Mail.MXRelay = true
	c.Mail.OnionRelay = false // Allow .onion addresses as MX relays
	c.Mail.Sender = ""
	c.Mail.Username = ""
	c.Mail.Password = ""
	c.Mail.OutboundName = "Anonymous Remailer"
	c.Mail.OutboundAddy = "remailer@domain.invalid"
	c.Mail.CustomFrom = false
	c.Stats.Minrel = 98.0
	c.Stats.Relfinal = 99.0
	c.Stats.Minlat = 2
	c.Stats.Maxlat = 60
	c.Stats.Chain = "*,*,*"
	c.Stats.Numcopies = 1
	c.Stats.Distance = 2
	c.Stats.StaleHrs = 24
	c.Stats.UseExpired = false
	c.Pool.Size = 5 // Good for startups, too small for established
	c.Pool.Rate = 65
	c.Pool.MinSend = 5 // Only used in Binomial Mix Pools
	c.Pool.Loop = 300
	c.Pool.MaxAge = 28
	c.Remailer.Name = "anon"
	c.Remailer.Address = "mix@nowhere.invalid"
	c.Remailer.Exit = false
	c.Remailer.MaxSize = 12
	c.Remailer.IDexp = 14
	c.Remailer.ChunkExpire = 60
	// Discard messages if packet timestamp exceeds this age in days
	c.Remailer.MaxAge = 14
	c.Remailer.Keylife = 14
	c.Remailer.Keygrace = 28
	c.Remailer.Daemon = false
	return c
}

// ParseConfig returns an instance of Config with defaults overridden by the content of a config file
func (f *Flags) ParseConfig() (*Config, error) {
	// Fetch an instance of Config with defaults predefined
	c := f.newConfig()
	// Try (really hard) to locate a yamn config file
	cfgFile, err := f.findConfig()
	if err == nil {
		// Useful for informing the user what config file is being read
		c.Files.Config = cfgFile
		yamlBytes, err := os.ReadFile(cfgFile)
		if err != nil {
			return nil, err
		}
		// Unmarshal the content of the YAML config file over the existing struct instance
		err = yaml.Unmarshal(yamlBytes, &c)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}
