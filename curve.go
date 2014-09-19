// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
)

const (
	version string = "0.1a"
	date_format string = "2006-01-02"
	key_validity_days int = 60
	max_frag_length = 10230
	maxChainLength = 10
	base64_line_wrap = 40
	headerBytes = 512
	headersBytes = headerBytes * maxChainLength
	bodyBytes = 10240
)

func main() {
	var b []byte
	var err error
	flags()
	if flag_client {
		mixprep()
	} else {
		b, err = uncut("test.txt")
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(len(b))
}
