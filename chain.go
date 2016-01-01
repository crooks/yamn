// vim: tabstop=2 shiftwidth=2

package main

import (
	"errors"
	"fmt"
	"github.com/crooks/yamn/keymgr"
	"os"
)

// distanceCriteria enforces user-defined minimal distance criteria
func distanceCriteria(addresses, dist []string) (c []string) {
	for _, addy := range addresses {
		if IsMemberStr(addy, dist) {
			// Excluded due to distance
			continue
		}
		c = append(c, addy)
	}
	return
}

// makeChain takes a chain string and constructs a valid remailer chain
func makeChain(inChain []string) (outChain []string, err error) {
	// If the chain contains a random remailer, we're going to need stats
	if IsMemberStr("*", inChain) {
		// Check modification timestamp on stats file
		var statRefresh bool
		statRefresh, err = Pubring.StatRefresh()
		if err != nil {
			Info.Println(err)
			err = errors.New("Cannot use random remailers without stats")
			return
		}
		if statRefresh {
			err = Pubring.ImportStats()
			if err != nil {
				Warn.Printf("Unable to read stats: %s", err)
				return
			}
		}
		// Check generated timestamp from stats file
		if Pubring.StatsStale(cfg.Stats.StaleHrs) {
			Warn.Println("Stale stats.  Generated age exceeds configured",
				fmt.Sprintf("threshold of %d hours", cfg.Stats.StaleHrs))
		}
	}
	dist := cfg.Stats.Distance
	if dist > maxChainLength {
		dist = maxChainLength
	}
	var candidates []string // Candidate remailers for each hop
	if len(inChain) > maxChainLength {
		fmt.Fprintf(os.Stderr, "%d hops exceeds maximum of %d\n", len(inChain), maxChainLength)
		os.Exit(1)
	}
	// If dist is greater than the actual chain length, all hops will be unique.
	if dist > len(inChain) {
		dist = len(inChain)
	}
	var distance []string
	in_dist := make([]string, 0, dist)  // n distance elements of input chain
	out_dist := make([]string, 0, dist) // n distance elements of output chain
	outChain = make([]string, 0, len(inChain))
	// Loop until inChain contains no more remailers
	num_hops := len(inChain)
	var hop string
	for {
		hop = popstr(&inChain)
		if hop == "*" {
			// Random remailer selection
			if len(outChain) == 0 {
				// Construct a list of suitable exit remailers
				candidates = Pubring.Candidates(
					cfg.Stats.Minlat,
					cfg.Stats.Maxlat,
					cfg.Stats.Relfinal,
					true)
			} else {
				// Construct a list of all suitable remailers
				candidates = Pubring.Candidates(
					cfg.Stats.Minlat,
					cfg.Stats.Maxlat,
					cfg.Stats.Minrel,
					false)
			}
			if len(candidates) > 0 {
				// Apply distance criteria
				candidates = distanceCriteria(candidates, distance)
				if len(candidates) == 0 {
					Warn.Println("Insufficient remailers to comply with distance criteria")
				}
			} else {
				Warn.Println("No candidate remailers match selection criteria")
			}

			if len(candidates) == 0 && flag_remailer {
				Warn.Println("Relaxing latency and uptime criteria to build chain")
				if len(outChain) == 0 {
					// Construct a list of suitable exit remailers
					candidates = Pubring.Candidates(0, 480, 0, true)
				} else {
					// Construct a list of all suitable remailers
					candidates = Pubring.Candidates(0, 480, 0, false)
				}
			} else if len(candidates) == 0 {
				// Insufficient remailers meet criteria and we're a client, so die.
				os.Exit(1)
			}
			if len(candidates) == 0 {
				errors.New("No remailers available to build random chain link")
				return
			}
			hop = candidates[randomInt(len(candidates)-1)]
		} else {
			var remailer keymgr.Remailer
			remailer, err = Pubring.Get(hop)
			if err != nil {
				return
			}
			hop = remailer.Address
		}
		// Extend outChain by 1 element
		outChain = outChain[0 : len(outChain)+1]
		// Shuffle existing entries to the right
		copy(outChain[1:], outChain[:len(outChain)-1])
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
			in_dist = inChain[len(inChain)-dist:]
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
