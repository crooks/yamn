package main

import (
	"fmt"

	"github.com/Masterminds/log-go"
)

type statistics struct {
	inDummy    int
	inMail     int
	inRemFoo   int
	inYamn     int
	outDummy   int
	outMail    int
	outYamn    int
	outLoop    int
	outRandhop int
	outPlain   int
}

func (s *statistics) reset() {
	s.inDummy = 0
	s.inMail = 0
	s.inYamn = 0
	s.inRemFoo = 0
	s.outDummy = 0
	s.outMail = 0
	s.outYamn = 0
	s.outLoop = 0
	s.outRandhop = 0
	s.outPlain = 0
	log.Info("Daily stats reset")
}

func (s *statistics) report() {
	log.Infof(
		"MailIn=%d, RemFoo=%d, YamnIn=%d, DummyIn=%d",
		s.inMail,
		s.inRemFoo,
		s.inYamn,
		s.inDummy,
	)
	line1 := fmt.Sprintf(
		"MailOut=%d, YamnOut=%d, YamnLoop=%d, Randhop=%d, ",
		s.outMail,
		s.outYamn,
		s.outLoop,
		s.outRandhop,
	)
	line2 := fmt.Sprintf(
		"FinalOut=%d, DummyOut=%d",
		s.outPlain,
		s.outDummy,
	)
	log.Infof(line1 + line2)
}

var stats = new(statistics)
