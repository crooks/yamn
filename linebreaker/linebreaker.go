package linebreaker

import (
	"io"
)

// lineBreaker breaks data across several lines, all of the same byte length
// (except possibly the last). Lines are broken with a single '\n'.
type lineBreaker struct {
	lineLength  int
	line        []byte
	used        int
	out         io.Writer
	haveWritten bool
}

func NewLineBreaker(out io.Writer, lineLength int) *lineBreaker {
	return &lineBreaker{
		lineLength: lineLength,
		line:       make([]byte, lineLength),
		used:       0,
		out:        out,
	}
}

func (l *lineBreaker) Write(b []byte) (n int, err error) {
	n = len(b)

	if n == 0 {
		return
	}

	if l.used == 0 && l.haveWritten {
		_, err = l.out.Write([]byte{'\n'})
		if err != nil {
			return
		}
	}

	if l.used+len(b) < l.lineLength {
		l.used += copy(l.line[l.used:], b)
		return
	}

	l.haveWritten = true
	_, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := l.lineLength - l.used
	l.used = 0

	_, err = l.out.Write(b[0:excess])
	if err != nil {
		return
	}

	_, err = l.Write(b[excess:])
	return
}

func (l *lineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
		if err != nil {
			return
		}
	}

	return
}
