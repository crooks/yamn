// vim: tabstop=2 shiftwidth=2

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/crooks/yamn/crandom"
	"github.com/crooks/yamn/keymgr"
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
	// Test if stats file has been modified since last imported
	if Pubring.StatRefresh() {
		// Try and import the modified stats file
		err = Pubring.ImportStats()
		if err != nil {
			Warn.Printf("Unable to read stats: %s", err)
			return
		}
		Info.Println("Stats updated and reimported")
	}
	// Check generated timestamp from stats file
	if Pubring.HaveStats() && Pubring.StatsStale(cfg.Stats.StaleHrs) {
		Warn.Printf(
			"Stale stats.  Generated age exceeds "+
				"configured threshold of %d hours",
			cfg.Stats.StaleHrs,
		)
	}
	// If the chain contains a random remailer, we're going to need stats
	if !Pubring.HaveStats() && IsMemberStr("*", inChain) {
		err = errors.New("Cannot use random remailers without stats")
		Warn.Println(err)
		return
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
	inDist := make([]string, 0, dist)  // n distance elements of input chain
	outDist := make([]string, 0, dist) // n distance elements of output chain
	outChain = make([]string, 0, len(inChain))
	// Loop until inChain contains no more remailers
	numHops := len(inChain)
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

			if len(candidates) == 0 && flagRemailer {
				Warn.Println("Relaxing latency and uptime criteria to build chain")
				if len(outChain) == 0 {
					// Construct a list of suitable exit remailers
					Info.Println("Constructing relaxed list of Exit remailers")
					candidates = Pubring.Candidates(0, 480, 0, true)
					Info.Printf(
						"Discovered %d Exit Remailers matching relaxed criteria",
						len(candidates),
					)
				} else {
					// Construct a list of all suitable remailers
					Info.Println("Constructing relaxed list of candidate remailers")
					candidates = Pubring.Candidates(0, 480, 0, false)
					Info.Printf(
						"Discovered %d candidate Remailers matching relaxed criteria",
						len(candidates),
					)
				}
			} else if len(candidates) == 0 {
				// Insufficient remailers meet criteria and we're a client, so die.
				os.Exit(1)
			}
			if len(candidates) == 0 {
				err = errors.New(
					"No remailers available to build " +
						"random chain link",
				)
				return
			} else if len(candidates) == 1 {
				hop = candidates[0]
				Warn.Printf(
					"Only one remailer (%s) meets chain "+
						"criteria",
					hop,
				)
			} else {
				hop = candidates[crandom.RandomInt(len(candidates))]
			}
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
			outDist = outChain[:dist]
		} else {
			outDist = outChain
		}
		if len(inChain) > dist {
			inDist = inChain[len(inChain)-dist:]
		} else {
			inDist = inChain
		}
		distance = append(inDist, outDist...)
	}
	if len(outChain) != numHops {
		panic("Constructed chain length doesn't match input chain length")
	}
	return
}
