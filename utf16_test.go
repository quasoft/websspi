package websspi_test

import (
	"syscall"
	"testing"

	"github.com/quasoft/websspi"
)

const maxmaxlen = 1024

var testcases = []struct {
	utf16  []uint16
	result string
	maxlen int
}{
	{
		utf16:  syscall.StringToUTF16("Hello World!"),
		result: "", // empty string if sequence longer than maxlen
		maxlen: 5,
	},
	{
		utf16:  syscall.StringToUTF16("Hello World!"),
		result: "Hello World!",
		maxlen: maxmaxlen,
	},
	{
		utf16:  []uint16{0},
		result: "",
		maxlen: maxmaxlen,
	},
	{
		utf16:  nil,
		result: "",
		maxlen: maxmaxlen,
	},
}

func TestUTF16PtrToString(t *testing.T) {
	for i, c := range testcases {
		var ptr *uint16
		if c.utf16 != nil {
			ptr = &c.utf16[0]
		}

		if r := websspi.UTF16PtrToString(ptr, c.maxlen); r != c.result {
			t.Errorf("#%d: Got %q instead of %q", i, r, c.result)
		}
	}
}
