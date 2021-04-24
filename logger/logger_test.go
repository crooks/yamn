package logger

import (
	"os"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/logfmt"
	"github.com/apex/log/handlers/text"
)

func TestConsoleLogger(t *testing.T) {
	log.SetHandler(text.New(os.Stderr))
	log.Info("Hello world")
}

func TestFileLogger(t *testing.T) {
	filename := "/tmp/foo/logger_test.log"
	logfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.WithError(err).WithField("file", filename).Error("This is an error")
		t.Fatalf("Could not open %s for logger", filename)
	}
	log.SetHandler(logfmt.New(logfile))
	log.Info("Successfully wrote a log entry")
	logfile.Close()
}
