package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestFlags(t *testing.T) {
	expectedClient := false
	expectedCopies := 0
	f := ParseFlags()
	if f.Client != expectedClient {
		t.Errorf("Expected Client to contain \"%v\" but got \"%v\".", expectedClient, f.Client)
	}
	if f.Copies != expectedCopies {
		t.Errorf("Expected Client to contain \"%v\" but got \"%v\".", expectedCopies, f.Copies)
	}
}

func TestConfig(t *testing.T) {
	testFile, err := ioutil.TempFile("/tmp", "yamn")
	if err != nil {
		t.Fatalf("Unable to create TempFile: %v", err)
	}
	defer os.Remove(testFile.Name())
	fakeCfg := `---
general:
  logtofile: true
  loglevel: info
files:
  pubkey: /fake/dir/pubkey
`
	testFile.WriteString(fakeCfg)
	testFile.Close()
	f := new(Flags)
	// Populate the Config flag with the new testFile name.  This will override any other yamn config files that might
	// be lurking.
	f.Config = testFile.Name()
	// act as if we've been called with --dir=/fakedir
	f.Dir = "/fakedir"
	c, err := f.ParseConfig()
	if err != nil {
		t.Fatalf("ParseConfig returned: %v", err)
	}
	// c.Files.Config is special, it returns the name of the processed YAML file
	if c.Files.Config != testFile.Name() {
		t.Errorf("expected c.Files.Config to contain \"%s\" but got \"%s\"", testFile.Name(), c.Files.Config)
	}
	// These settings are defined in the fake config
	if !c.General.LogToFile {
		t.Errorf("expected c.General.Loglevel to be true but got %v", c.General.LogToFile)
	}
	if c.General.Loglevel != "info" {
		t.Errorf("expected c.General.Loglevel to contain \"info\" but got \"%s\"", c.General.Loglevel)
	}
	if c.Files.Pubkey != "/fake/dir/pubkey" {
		t.Errorf("expected c.Files.Pubkey to contain \"/fake/dir/pubkey\" but got \"%s\"", c.Files.Pubkey)
	}
	// These settings are undefined and should return defaults
	if !c.Urls.Fetch {
		t.Errorf("expected c.Urls.Fetch to default to true but got %v", c.Urls.Fetch)
	}
	if !c.Mail.UseTLS {
		t.Errorf("expected c.Mail.UseTLS to default to true but got %v", c.Mail.UseTLS)
	}
	// These settings inherit defaults from flags
	if c.Files.IDlog != "/fakedir/idlog" {
		t.Errorf("Expected c.Files.IDlog to default to \"/fakedir/idlog\" but got \"%s\".", c.Files.IDlog)
	}
}
