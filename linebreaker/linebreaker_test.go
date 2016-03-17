package linebreaker

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"testing"
)

func testText() string {
	return `’Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe.

“Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!”

He took his vorpal sword in hand;
Long time the manxome foe he sought—
So rested he by the Tumtum tree
And stood awhile in thought.

And, as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

“And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!”
He chortled in his joy.

’Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe.`
}

// wrap64 writes a byte payload as wrapped base64 to an io.writer
func wrap64(writer io.Writer, b []byte, wrap int) {
	breaker := NewLineBreaker(writer, wrap)
	b64 := base64.NewEncoder(base64.StdEncoding, breaker)
	b64.Write(b)
	b64.Close()
	breaker.Close()
}

func TestWrap(t *testing.T) {
	inText := []byte(testText())
	buf := new(bytes.Buffer)
	writer := bufio.NewWriter(buf)
	wrap64(writer, inText, 64)
	writer.Flush()
	outText := make([]byte, base64.StdEncoding.DecodedLen(buf.Len()))
	n, err := base64.StdEncoding.Decode(outText, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(inText, outText[:n]) != 0 {
		t.Fatal("Input/Output Mismatch")
	}
}
