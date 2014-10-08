// vim: tabstop=2 shiftwidth=2

package main

import (
	"os"
	"fmt"
	"github.com/crooks/yamn/keymgr"
)

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
func chain_build(inChain []string, pubring *keymgr.Pubring) (outChain []string, err error) {
	dist := cfg.Stats.Distance
	if dist > maxChainLength {
		dist = maxChainLength
	}
	var addresses []string // Candidate remailers for each hop
	if len(inChain) > maxChainLength {
		fmt.Fprintf(os.Stderr, "%d hops exceeds maximum of %d\n", len(inChain), maxChainLength)
		os.Exit(1)
	}
	// If dist is greater than the actual chain length, all hops will be unique.
	if dist > len(inChain) {
		dist = len(inChain)
	}
	var distance []string
	in_dist := make([]string,0, dist) // n distance elements of input chain
	out_dist := make([]string,0, dist) // n distance elements of output chain
	outChain = make([]string, 0, len(inChain))
	// Loop until inChain contains no more remailers
	num_hops := len(inChain)
	var hop string
	for {
		hop = popstr(&inChain)
		if hop == "*" {
			// Check modification timestamp on stats file
			if pubring.StatRefresh() {
				err = pubring.ImportStats()
				if err != nil {
					Warn.Printf("Unable to read stats: %s", err)
					return
				}
			}
			// Check generated timestamp from stats file
			if pubring.StatsStale(cfg.Stats.StaleHrs) {
				Warn.Println("Stale stats.  Generated age exceeds configured",
					fmt.Sprintf("threshold of %d hours", cfg.Stats.StaleHrs))
			}
			// Random remailer selection
			if len(outChain) == 0 {
				// Construct a list of suitable exit remailers
				addresses = pubring.Candidates(cfg.Stats.Minlat, cfg.Stats.Maxlat, cfg.Stats.Relfinal, true)
			} else {
				// Construct a list of all suitable remailers
				addresses = pubring.Candidates(cfg.Stats.Minlat, cfg.Stats.Maxlat, cfg.Stats.Minrel, false)
			}
			addresses = candidates(addresses, distance)
			hop = addresses[randomInt(len(addresses) - 1)]
		} else {
			var remailer keymgr.Remailer
			remailer, err = pubring.Get(hop)
			if err != nil {
				return
			}
			hop = remailer.Address
		}
		// Extend outChain by 1 element
		outChain = outChain[0:len(outChain) + 1]
		// Shuffle existing entries to the right
		copy(outChain[1:], outChain[:len(outChain) - 1])
		// Insert new hop at the start of the output chain
		outChain[0] = hop

		// Break out when the input chain is empty
		if len(inChain) == 0 {
			break
		}
		// The following section is concerned with distance parameter compliance
		if len(outChain) > dist {
			out_dist = outChain[:dist]
		} else {
			out_dist = outChain
		}
		if len(inChain) > dist {
			in_dist = inChain[len(inChain) - dist:]
		} else {
			in_dist = inChain
		}
		distance = append(in_dist, out_dist...)
	}
	if len(outChain) != num_hops {
		panic("Constructed chain length doesn't match input chain length")
	}
	return
}
