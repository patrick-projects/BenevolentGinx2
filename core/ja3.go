package core

import (
	"crypto/md5"
	"fmt"
	"strconv"
	"strings"
)

// GREASE values defined in RFC 8701 - these should be excluded from JA3
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func isGREASE(v uint16) bool {
	return greaseValues[v]
}

// ComputeJA3 computes the JA3 fingerprint string and hash from ClientHello components.
// Parameters:
//   - tlsVersion: TLS version from the ClientHello
//   - cipherSuites: cipher suite IDs
//   - extensions: extension type IDs
//   - ellipticCurves: supported curve IDs (from supported_groups extension)
//   - ecPointFormats: EC point format IDs
//
// Returns the JA3 hash (MD5 hex string) and the raw JA3 string.
func ComputeJA3(tlsVersion uint16, cipherSuites []uint16, extensions []uint16, ellipticCurves []uint16, ecPointFormats []uint8) (string, string) {
	// Filter out GREASE values
	var filteredCiphers []string
	for _, cs := range cipherSuites {
		if !isGREASE(cs) {
			filteredCiphers = append(filteredCiphers, strconv.Itoa(int(cs)))
		}
	}

	var filteredExtensions []string
	for _, ext := range extensions {
		if !isGREASE(ext) {
			filteredExtensions = append(filteredExtensions, strconv.Itoa(int(ext)))
		}
	}

	var filteredCurves []string
	for _, curve := range ellipticCurves {
		if !isGREASE(curve) {
			filteredCurves = append(filteredCurves, strconv.Itoa(int(curve)))
		}
	}

	var filteredFormats []string
	for _, pf := range ecPointFormats {
		filteredFormats = append(filteredFormats, strconv.Itoa(int(pf)))
	}

	// Build JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(filteredCiphers, "-"),
		strings.Join(filteredExtensions, "-"),
		strings.Join(filteredCurves, "-"),
		strings.Join(filteredFormats, "-"),
	)

	// Compute MD5 hash
	hash := md5.Sum([]byte(ja3String))
	ja3Hash := fmt.Sprintf("%x", hash)

	return ja3Hash, ja3String
}

// ParseExtensionTypes extracts extension type IDs from a raw ClientHello message.
// The raw bytes should be the ClientHello handshake message (starting from the handshake type byte).
func ParseExtensionTypes(raw []byte) []uint16 {
	if len(raw) < 42 {
		return nil
	}

	// Skip: handshake_type(1) + length(3) + version(2) + random(32) = 38
	// Then: session_id_length(1) + session_id(N)
	offset := 38
	if offset >= len(raw) {
		return nil
	}
	sessionIDLen := int(raw[offset])
	offset += 1 + sessionIDLen

	// cipher_suites_length(2) + cipher_suites(N)
	if offset+2 > len(raw) {
		return nil
	}
	cipherSuitesLen := int(raw[offset])<<8 | int(raw[offset+1])
	offset += 2 + cipherSuitesLen

	// compression_methods_length(1) + compression_methods(N)
	if offset >= len(raw) {
		return nil
	}
	compressionLen := int(raw[offset])
	offset += 1 + compressionLen

	// extensions_length(2)
	if offset+2 > len(raw) {
		return nil
	}
	extensionsLen := int(raw[offset])<<8 | int(raw[offset+1])
	offset += 2

	end := offset + extensionsLen
	if end > len(raw) {
		end = len(raw)
	}

	var extensions []uint16
	for offset+4 <= end {
		extType := uint16(raw[offset])<<8 | uint16(raw[offset+1])
		extLen := int(raw[offset+2])<<8 | int(raw[offset+3])
		extensions = append(extensions, extType)
		offset += 4 + extLen
	}

	return extensions
}
