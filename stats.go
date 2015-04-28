package main

import ()

type statistics struct {
	inDummy    int
	inMail     int
	inEnc      int
	inRemFoo   int
	outDummy   int
	outMail    int
	outEnc     int
	outLoop    int
	outRandhop int
	outPlain   int
}

func (s *statistics) reset() {
	s.inDummy = 0
	s.inMail = 0
	s.inEnc = 0
	s.inRemFoo = 0
	s.outDummy = 0
	s.outMail = 0
	s.outEnc = 0
	s.outLoop = 0
	s.outRandhop = 0
	s.outPlain = 0
}

func (s *statistics) report() {
	Info.Printf(
		"MailIn=%d, RemFoo=%d, YamnIn=%d, DummyIn=%d",
		s.inMail,
		s.inRemFoo,
		s.inEnc,
		s.inDummy,
	)
	Info.Printf(
		"MailOut=%d, YamnOut=%d, YamnLoop=%d, Randhop=%d,",
		"FinalOut=%d, DummyOut=%d",
		s.outMail,
		s.outEnc,
		s.outLoop,
		s.outRandhop,
		s.outPlain,
		s.outDummy,
	)
}

var stats = new(statistics)
