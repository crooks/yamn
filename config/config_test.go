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
	fakeCfg := new(Config)
	fakeCfg.General.LogToFile = true
	fakeCfg.General.Loglevel = "info"
	fakeCfg.WriteConfig(testFile.Name())

	cfg, err := ParseConfig(testFile.Name())
	if err != nil {
		t.Fatalf("ParseConfig returned: %v", err)
	}

	if cfg.General.LogToFile != fakeCfg.General.LogToFile {
		t.Fatalf("Expected cfg.General.Loglevel to contain \"%v\" but got \"%v\".", fakeCfg.General.LogToFile, cfg.General.LogToFile)
	}
	if cfg.General.Loglevel != fakeCfg.General.Loglevel {
		t.Fatalf("Expected cfg.General.Loglevel to contain \"%s\" but got \"%s\".", fakeCfg.General.Loglevel, cfg.General.Loglevel)
	}
}
