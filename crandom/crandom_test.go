package crandom

import (
	"testing"
)

// makeRange creates a slice of integers in numeric order between min and max (inclusive)
func makeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

// contains tests if an integer is a member of a slice
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// sum totals all the integers in a slice
func sum(s []int) (t int) {
	for _, i := range s {
		t += i
	}
	return
}

// sumAsc totals all the bytes in a subset(r) of a slice of strings.
func sumAsc(asc []string, r int) (t int) {
	for _, s := range asc[0:r] {
		chars := []byte(s)
		for _, c := range chars {
			t += int(c)
		}
	}
	return
}

func TestDice(t *testing.T) {
	i := Dice()
	if i < 0 || i > 255 {
		t.Fatalf("Dice should return 0-255.  Got: %d", i)
	}
}

func TestInt(t *testing.T) {
	for i := 0; i < 100; i++ {
		i := RandomInt(3)
		if i < 0 || i > 2 {
			t.Fatalf("Random integer out of range: %d", i)
		}
	}
}

func TestRandInts(t *testing.T) {
	testLen := 50
	is := RandInts(testLen)
	seq := makeRange(0, testLen-1)
	if len(is) != len(seq) {
		t.Fatalf("Incorrect sequence length.  Expected=%d, Got=%d", len(seq), len(is))
	}
	if sum(is) != sum(seq) {
		t.Fatalf("Sum of sequence not equal to sum of randomized slice.  Expected=%d, Got=%d", sum(seq), sum(is))
	}
	inSeq := 0
	for i := range seq {
		if !contains(is, i) {
			t.Fatalf("Random range does not include element: %d", i)
		}
		if is[i] == i {
			inSeq++
		}
		if inSeq > testLen/10 {
			t.Errorf("Suspiciously high number of sequence n in slice n. Collisions=%d", inSeq)
		}
	}
}

func TestShuffle(t *testing.T) {
	start := 48
	end := 122
	shuffleText := make([]string, end-start+1)
	for n := 0; n <= end-start; n++ {
		shuffleText[n] = string(rune(n + start))
	}
	// Compare the total byte values of all the chars before and after a shuffle.  They should match.
	preSum := sumAsc(shuffleText, len(shuffleText))
	Shuffle(shuffleText)
	postSum := sumAsc(shuffleText, len(shuffleText))
	if preSum != postSum {
		t.Fatalf("Mismatched sum of acsii chars before and after shuffle. Before=%d, After=%d", preSum, postSum)
	}
	// Compare the total byte values of all the chars in a subsection of the slice.  They should not match.
	preSum = sumAsc(shuffleText, 10)
	Shuffle(shuffleText)
	postSum = sumAsc(shuffleText, 10)
	if preSum == postSum {
		t.Fatal("Bad shuffle. Substring match in shuffled text.")
	}
}

func TestRandBytes(t *testing.T) {
	sampleLength := 100
	rb := Randbytes(sampleLength)
	if len(rb) != sampleLength {
		t.Fatalf("Mismatched byte count.  Expected=%d, Got=%d", sampleLength, len(rb))
	}
	// Count the occurances of each byte in random data.  Fail if too many collisions occur.
	threshold := (sampleLength / 100) * 5 // 5% of whole sample
	m := make(map[byte]int)
	for _, b := range rb {
		m[b]++
		if m[b] > threshold {
			t.Errorf("Suspiciously high number of matching bytes in random data. Byte=%d, Count=%d", b, m[b])
		}
	}
}
