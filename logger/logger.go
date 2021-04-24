package logger

import (
	"os"

	"github.com/apex/log"
	"github.com/apex/log/handlers/logfmt"
)

func New(filename string) {
	logfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		t.Fatalf("Could not open %s for logger", filename)
	}
	log.SetHandler(logfmt.New(logfile))
}
