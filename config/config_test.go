package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestFlags(t *testing.T) {
	expectedClient := false
	expectedCopies := 0
	expectedConfig := "/etc/yamn/fake.yml"
	// This needs to be set prior to doing ParseFlags()
	os.Setenv("YAMNCFG", expectedConfig)
	f := ParseFlags()
	if f.Client != expectedClient {
		t.Fatalf("Expected Client to contain \"%v\" but got \"%v\".", expectedClient, f.Client)
	}
	if f.Copies != expectedCopies {
		t.Fatalf("Expected Client to contain \"%v\" but got \"%v\".", expectedCopies, f.Copies)
	}
	if f.Config != expectedConfig {
		t.Fatalf("Expected Client to contain \"%v\" but got \"%v\".", expectedConfig, f.Config)
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
	// Populate the Config flag with the new testFile name
	f.Config = testFile.Name()
	// act as if we've been called with --dir=/fakedir
	f.Dir = "/fakedir"
	cfg, err := f.ParseConfig()
	if err != nil {
		t.Fatalf("ParseConfig returned: %v", err)
	}

	// These settings are defined in the fake config
	if !cfg.General.LogToFile {
		t.Errorf("expected cfg.General.Loglevel to be true but got %v", cfg.General.LogToFile)
	}
	if cfg.General.Loglevel != "info" {
		t.Errorf("expected cfg.General.Loglevel to contain \"info\" but got \"%s\"", cfg.General.Loglevel)
	}
	if cfg.Files.Pubkey != "/fake/dir/pubkey" {
		t.Errorf("expected cfg.Files.Pubkey to contain \"/fake/dir/pubkey\" but got \"%s\"", cfg.Files.Pubkey)
	}
	// These settings are undefined and should return defaults
	if !cfg.Urls.Fetch {
		t.Errorf("expected cfg.Urls.Fetch to default to true but got %v", cfg.Urls.Fetch)
	}
	if !cfg.Mail.UseTLS {
		t.Errorf("expected cfg.Mail.UseTLS to default to true but got %v", cfg.Mail.UseTLS)
	}
	// These settings inherit defaults from flags
	if cfg.Files.IDlog != "/fakedir/idlog" {
		t.Errorf("Expected cfg.Files.IDlog to default to \"/fakedir/idlog\" but got \"%s\".", cfg.Files.IDlog)
	}
}
