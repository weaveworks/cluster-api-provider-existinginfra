package encoding

import "encoding/base64"

// This file contains a util to base64 strings for editing secrets

func Base64Encode(s string) []byte {
	strLen := base64.StdEncoding.EncodedLen(len(s))
	sB64 := make([]byte, strLen)
	base64.StdEncoding.Encode(sB64, []byte(s))
	return sB64
}
