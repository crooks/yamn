// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"fmt"
	"github.com/crooks/yamn/keymgr"
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
func candidates(addresses, dist []string) (c []string) {
	c = make([]string, 0, len(addresses))
  for _, addy := range addresses {
		if str_contains(addy, dist) {
			// Excluded due to distance
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
func chain_build(in_chain []string, pubring *keymgr.Pubring) (out_chain []string) {
	dist := cfg.Stats.Distance
	if dist > maxChainLength {
		dist = maxChainLength
	}
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
	// Loop until in_chain contains no more remailers
	num_hops := len(in_chain)
	var hop string
	for {
		hop = popstr(&in_chain)
		if hop == "*" {
			// Random remailer selection
			if len(out_chain) == 0 {
				// Construct a list of suitable exit remailers
				addresses = pubring.Candidates(cfg.Stats.Minlat, cfg.Stats.Maxlat, cfg.Stats.Relfinal, true)
			} else {
				// Construct a list of all suitable remailers
				addresses = pubring.Candidates(cfg.Stats.Minlat, cfg.Stats.Maxlat, cfg.Stats.Minrel, false)
			}
			addresses = candidates(addresses, distance)
			hop = addresses[randomInt(len(addresses) - 1)]
		} else {
			remailer, err := pubring.Get(hop)
			if err != nil {
				return
			}
			hop = remailer.Address
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
