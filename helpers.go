package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"unicode"
)

// addPadding appends ISO/IEC 7816-4 padding to a byte slice
func addPadding(unpadded []byte) ([]byte, error) {
	paddingAmountBig, err := rand.Int(rand.Reader, big.NewInt(255))
	if err != nil {
		return []byte{}, err
	}
	paddingAmount := byte(paddingAmountBig.Int64())
	// slice will be  {0x00,0x00...,0x00}
	padding := make([]byte, paddingAmount)
	padding[0] = 0x80
	return append(unpadded, padding...), nil
}

// removePadding removes ISO/IEC 7816-4 padding from a byte slice
func removePadding(padded []byte) ([]byte, error) {
	unpadded := bytes.TrimRight(padded, "\x00")
	if unpadded[len(unpadded)-1] != 0x80 {
		return []byte{}, errors.New("Invalid padding!")
	}
	return unpadded[:len(unpadded)-1], nil
}

// unpackTXT decodes TXT packing
// from the miekg/dns docs:
// > For TXT character strings, tabs, carriage returns and line feeds will be converted to \t, \r and \n respectively.
// > Back slashes and quotations marks will be escaped. Bytes below 32 and above 127 will be converted to \DDD form.
func unpackTXT(txt []byte) ([]byte, error) {
	unpackedTXT := make([]byte, len(txt))

	j := 0
	i := 0
	for ; j < len(txt); i++ {
		// Have slash?
		if txt[j] == 0x5C {
			j++
			if j == len(txt) {
				break
			}
			// look for \DDD sequence
			if j+2 < len(txt) && unicode.IsDigit(rune(txt[j])) && unicode.IsDigit(rune(txt[j+1])) && unicode.IsDigit(rune(txt[j+2])) {
				// parse DDD as decimal integer
				byteVal, err := strconv.Atoi(string(txt[j : j+3]))
				if err != nil {
					return unpackedTXT, err
				}
				// the three digits represented a byte in the first place
				// so this coversion should be safe
				unpackedTXT[i] = byte(byteVal)
				j += 3
			} else {
				// it is a escape sequence like \n. decode it.
				switch txt[j] {
				case 'n':
					unpackedTXT[i] = '\n'
				case 't':
					unpackedTXT[i] = '\t'
				case 'r':
					unpackedTXT[i] = '\r'
				default:
					j++
					return unpackedTXT, fmt.Errorf("%s", "Invalid slash escaped character found!")
				}
				j++
			}
		} else {
			// it is a printable character, so we just copy it
			unpackedTXT[i] = txt[j]
			j++
		}
	}
	return unpackedTXT[0:i], nil
}
