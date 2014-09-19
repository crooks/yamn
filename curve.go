// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"os"
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

func server(header []byte, sec map[string][]byte) (final slotFinal) {
	slotData, auth, err := decode_head(header, sec)
	if err != nil {
		panic(err)
	}
	if ! auth {
		fmt.Fprintln(os.Stderr, "Auth failed ECC decoding slot data")
	}
	data, err := decode_data(slotData)
	if err != nil {
		panic(err)
	}
	if data.packetType == 1 {
		final, err = decodeFinal(data.packetInfo)
		if err != nil {
			panic(err)
		}
	}
	return
}


func main() {
	flags()
	mixprep()
}
