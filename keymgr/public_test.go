package keymgr

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWritePubring(t *testing.T) {
	f, err := os.Create("pubring.mix")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var options string
	for n := 0; n < 10; n++ {
		counter := fmt.Sprintf("%02d", n)
		keyid := strings.Repeat("0", 32-len(counter)) + counter
		key := strings.Repeat("0", 32) + keyid
		if n < 4 {
			options = "E"
		} else {
			options = "M"
		}
		header := fmt.Sprintf(
			"test%02d test%02d@domain.foo %s 4:0.2a %s 2016-01-01 2100-12-31\n\n",
			n,
			n,
			keyid,
			options,
		)
		f.WriteString(header)
		f.WriteString("-----Begin Mix Key-----\n")
		f.WriteString(keyid + "\n")
		f.WriteString(key + "\n")
		f.WriteString("-----End Mix Key-----\n\n")
	}
}

func TestWriteMlist2(t *testing.T) {
	f, err := os.Create("mlist2.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("Stats-Version: 2.0\n")
	now := time.Now()
	gentime := now.Add(-90 * time.Minute)
	genstamp := fmt.Sprintf("Generated: %s\n", gentime.Format(generatedFormat))
	f.WriteString(genstamp)
	f.WriteString("Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options\n")
	f.WriteString(strings.Repeat("-", 64) + "\n")
	var options string
	for n := 0; n < 10; n++ {
		name := fmt.Sprintf("test%02d", n)
		lathist := strings.Repeat("0", 12)
		latent := fmt.Sprintf("   :%02d  ", n)
		uphist := strings.Repeat("+", 12)
		uptime := fmt.Sprintf(" %3d.0%% ", 100-(n*5))
		if n < 4 {
			options = ""
		} else {
			options = "D"
		}
		header := fmt.Sprintf(
			"%-12s %s %s %s %s %s\n",
			name,
			lathist,
			latent,
			uphist,
			uptime,
			options,
		)
		f.WriteString(header)
	}
	f.WriteString("\nBroken type-I remailer chains:\n\n\n")
	f.WriteString("Broken type-II remailer chains:\n\n\n\n\n")
	f.WriteString("Remailer-Capabilities:\n\n")
	for n := 0; n < 10; n++ {
		name := fmt.Sprintf("test%02d", n)
		addy := fmt.Sprintf("%s@domain.foo", name)
		if n < 4 {
			options = ""
		} else {
			options = " middle"
		}
		header := fmt.Sprintf(
			"$remailer{\"%s\"} = \"<%s>%s\";\n",
			name,
			addy,
			options,
		)
		f.WriteString(header)
	}

}

func TestImport(t *testing.T) {
	p := NewPubring("pubring.mix", "mlist2.txt")
	err := p.ImportPubring()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Imported %d remailers from Public Keyring.\n", p.Count())
	for _, rem := range p.KeyList() {
		fmt.Println(rem)
	}
	// Stats haven't been imported yet
	if p.HaveStats() {
		t.Fatal("Stats not yet imported")
	}
	err = p.ImportStats()
	if err != nil {
		t.Fatal(err)
	}
	// Stats have been imported
	if !p.HaveStats() {
		t.Fatal("Stats should have been imported")
	}
	// Test if the pubring.mix file has been modified since we imported
	// it.  The expectation is that it won't have been.
	if p.KeyRefresh() {
		t.Fatal("Pubring should be fresh")
	}
	// Test if the mlist2.txt file has been modified since we imported
	// it.  The expectation is that it won't have been.
	if p.StatRefresh() {
		t.Fatal("Stats should be fresh")
	}
	// Test stats are 90 minutes old, they shouldn't be stale
	if p.StatsStale(2) {
		t.Fatal("Test Stats are over 2 hours old")
	}
}

func TestCandidates(t *testing.T) {
	p := NewPubring("pubring.mix", "mlist2.txt")
	err := p.ImportPubring()
	if err != nil {
		t.Fatal(err)
	}
	err = p.ImportStats()
	if err != nil {
		t.Fatal(err)
	}
	// Middleman Remailer candidates
	candidates := p.Candidates(1, 8, 70.0, false)
	numCandidates := len(candidates)
	fmt.Printf("Middle candidates: %d\n", numCandidates)
	if numCandidates != 6 {
		t.Fatalf("Expected 6 Middle candidates, got %d", numCandidates)
	}
	// Exit Remailer candidates
	candidates = p.Candidates(1, 8, 70.0, true)
	numCandidates = len(candidates)
	fmt.Printf("Exit candidates: %d\n", numCandidates)
	if numCandidates != 3 {
		t.Fatalf("Expected 3 Exit candidates, got %d", numCandidates)
	}
}
