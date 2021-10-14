package websspi

import (
	"unicode/utf16"
	"unsafe"
)

// UTF16PtrToString converts a pointer to a UTF-16 sequence to a string.
// The UTF-16 sequence must null terminated or shorter than maxLen.
//
// If the UTF-16 sequence is longer than maxlen, an empty string is returned.
func UTF16PtrToString(ptr *uint16, maxLen int) (s string) {
	if ptr == nil {
		return ""
	}

	buf := make([]uint16, 0, maxLen)
	for i, p := 0, unsafe.Pointer(ptr); i < maxLen; i, p = i+1, unsafe.Pointer(uintptr(p)+2) {
		char := *(*uint16)(p)
		if char == 0 {
			// Decode sequence and return
			return string(utf16.Decode(buf))
		}

		buf = append(buf, char)
	}
	// Return empty string once maxLen is reached.
	return ""
}
