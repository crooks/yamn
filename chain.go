// vim: tabstop=2 shiftwidth=2

package main

import (
	"crypto/rand"
	"math/big"
	"strings"
	"os"
	"fmt"
)

// popstr takes a pointer to a string slice and pops the last element
func popstr(s *[]string) (element string) {
	slice := *s
	element, slice = slice[len(slice) - 1], slice[:len(slice) - 1]
	*s = slice
	return
}

// insstr inserts a string (text) into a slice at position pos
func insstr(s *[]string, text string, pos int) (length int) {
	slice := *s
	slice = append(slice, "foo")
	copy(slice[pos + 1:], slice[pos:])
	slice[pos] = text
	*s = slice
	length = len(slice)
	return
}

// randint returns a cryptographically random number in range 0-max
func randint(max int) (rint int) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	rint = int(r.Uint64())
	return
}

// str_contains tests for the membership of a string in a slice
func str_contains(s string, slice []string) bool {
	for _, n := range slice {
		if n == s {
			return true
		}
	}
	return false
}

// candidates returns a slice of remailer addresses suitable for a given hop
func candidates(p map[string]pubinfo, dist []string, exit bool) (c []string) {
	c = make([]string, 0, len(p))
  // Create a slice of addresses (for random node selection)
  for addy := range p {
		if str_contains(addy, dist) {
			// Excluded due to distance
			continue
		}
		if exit {
			if strings.Contains(p[addy].caps, "M") {
				// Exits are required and this is a Middle
				continue
			}
			if p[addy].uptime < int(cfg.Stats.Relfinal * 10) {
				// Doesn't meet exit reliability requirements
				continue
			}
		} else {
			if p[addy].uptime < int(cfg.Stats.Minrel * 10) {
				// Doesn't meet reliability requirements
				continue
			}
		}
		if p[addy].latent > cfg.Stats.Maxlat || p[addy].latent < cfg.Stats.Minlat {
			// Doesn't meet latency requirements
			continue
		}
		c = append(c, addy)
	}
	if len(c) == 0 {
		fmt.Fprintln(os.Stderr, "Insufficient remailers meet chain criteria")
		os.Exit(1)
	}
	return
}

// chain_build takes a chain string and constructs a valid remailer chain
func chain_build(in_chain []string, pub map[string]pubinfo, xref map[string]string) (out_chain []string) {
	dist := cfg.Stats.Distance
	if dist > maxChainLength {
		dist = maxChainLength
	}
	var exist bool // Test for key existence
	var addresses []string // Candidate remailers for each hop
	if len(in_chain) > maxChainLength {
		fmt.Fprintf(os.Stderr, "%d hops exceeds maximum of %d\n", len(in_chain), maxChainLength)
		os.Exit(1)
	}
	// If dist is greater than the actual chain length, all hops will be unique.
	if dist > len(in_chain) {
		dist = len(in_chain)
	}
	var distance []string
	in_dist := make([]string,0, dist) // n distance elements of input chain
	out_dist := make([]string,0, dist) // n distance elements of output chain
	out_chain = make([]string, 0, len(in_chain))
	// This iteration of in_chain converts any shortnames to addresses
	for n, hop := range in_chain {
		if strings.Contains(in_chain[n], "@") {
			// Selection via remailer email address
			_, exist = pub[hop]
	    if ! exist {
				fmt.Fprintf(os.Stderr, "%s: Remailer address not known\n", hop)
				os.Exit(1)
			}
		} else if in_chain[n] != "*" {
			// Selection via remailer shortname
			_, exist = xref[hop]
			if ! exist {
				fmt.Fprintf(os.Stderr, "%s: Remailer shortname not known\n", hop)
				os.Exit(1)
			}
			// Change hop to its cross-reference by shortname
			in_chain[n] = xref[hop]
		}
	}
	// Loop until in_chain contains no more remailers
	num_hops := len(in_chain)
	for {
		hop := popstr(&in_chain)
		if hop == "*" {
			// Random remailer selection
			if len(out_chain) == 0 {
				// Construct a list of suitable exit remailers
				addresses = candidates(pub, distance, true)
			} else {
				// Construct a list of all suitable remailers
				addresses = candidates(pub, distance, false)
			}
			hop = addresses[randint(len(addresses) - 1)]
		}
		// Insert new hop at the start of the output chain
		_ = insstr(&out_chain, hop, 0)
		if len(in_chain) == 0 {
			break
		}
		// The following section is concerned with distance parameter compliance
		if len(out_chain) > dist {
			out_dist = out_chain[:dist]
		} else {
			out_dist = out_chain
		}
		if len(in_chain) > dist {
			in_dist = in_chain[len(in_chain) - dist:]
		} else {
			in_dist = in_chain
		}
		distance = append(in_dist, out_dist...)
	}
	if len(out_chain) != num_hops {
		panic("Constructed chain length doesn't match input chain length")
	}
	return
}
