// Package identifybin is a package for identifying the operating system, architecture, and endianess of a binary.
package identifybin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// DetectOSAndArch downloads the first n bytes of a file
func DetectOSAndArch(input interface{}) (BinaryType, error) {
	var b []byte
	var binType BinaryType
	var err error

	switch v := input.(type) {
	case string:
		b, err = os.ReadFile(v)
		if err != nil {
			return binType, err
		}
	case []byte:
		b = v
	default:
		return binType, errors.New("unsupported input type")
	}

	return detectOSAndArchFromBytes(b)
}

func detectOSAndArchFromBytes(b []byte) (BinaryType, error) {
	var binType BinaryType

	if len(b) < 256 {
		return binType, errors.New("binary too small")
	}

	switch {
	case bytes.HasPrefix(b, []byte(elfMagic)):
		return parseELF(b)
	case bytes.HasPrefix(b, []byte{0xFE, 0xED, 0xFA, 0xCE}) || bytes.HasPrefix(b, []byte{0xFE, 0xED, 0xFA, 0xCF}) || bytes.HasPrefix(b, []byte{0xCE, 0xFA, 0xED, 0xFE}) || bytes.HasPrefix(b, []byte{0xCF, 0xFA, 0xED, 0xFE}):
		return parseMachO(b)
	case bytes.HasPrefix(b, []byte(peMagic)):
		return parsePE(b)
	default:
		return binType, errors.New("unknown binary format")
	}
}

func parseELF(b []byte) (BinaryType, error) {
	var binType BinaryType
	binType.OperatingSystem = "linux"

	machine := b[18]
	switch machine {
	case 0x03:
		binType.Arch = "x86"
	case 0x3E:
		binType.Arch = "x86_64"
	case 0xB7:
		binType.Arch = "arm64"
	case 0x28:
		binType.Arch = "arm"
	default:
		return binType, errors.New("unsupported ELF architecture")
	}

	switch b[4] {
	case 1:
		binType.Endianess = "little-endien"
	case 2:
		binType.Endianess = "big-endien"
	}

	return binType, nil
}

func parseMachO(b []byte) (BinaryType, error) {
	var binType BinaryType
	binType.OperatingSystem = "darwin"

	var magic uint32

	buf := bytes.NewReader(b)

	err := binary.Read(buf, binary.BigEndian, &magic)
	if err != nil {
		return binType, err
	}

	isLE := (magic == 0xCAFEBABE) || (magic == 0xCAFED00D)
	var byteOrder binary.ByteOrder
	if isLE {
		byteOrder = binary.LittleEndian
		binType.Endianess = "little-endien"
	} else {
		byteOrder = binary.BigEndian
		binType.Endianess = "big-endien"
	}

	var cputype int32
	if (magic == 0xFEEDFACE) || (magic == 0xFEEDFACF) {
		err = binary.Read(buf, byteOrder, &cputype)
	} else {
		_, err = buf.Seek(8, 0)
		if err != nil {
			return binType, err
		}
		err = binary.Read(buf, byteOrder, &cputype)
	}
	if err != nil {
		return binType, err
	}

	switch cputype {
	case 7:
		binType.Arch = "x86"
	case 0x01000007, 0x3000000:
		binType.Arch = "x86_64"
	case 12:
		binType.Arch = "arm"
	case 0x0100000C, 0x0100000D, 0x0:
		binType.Arch = "arm64"
	default:
		return binType, fmt.Errorf("unsupported Mach-O architecture: 0x%x", cputype)
	}

	return binType, nil
}

func parsePE(b []byte) (BinaryType, error) {
	var binType BinaryType
	binType.OperatingSystem = "windows"
	binType.Endianess = "little-endien"

	// PE header offset
	peOffset := binary.LittleEndian.Uint32(b[0x3C:])
	machine := binary.LittleEndian.Uint16(b[peOffset+4:])

	switch machine {
	case 0x014C:
		binType.Arch = "x86"
	case 0x8664:
		binType.Arch = "x86_64"
	case 0xAA64:
		binType.Arch = "arm64"
	default:
		return binType, errors.New("unsupported PE architecture")
	}

	return binType, nil
}

// DownloadFirstNBytes downloads the first N bytes of a file from a URL.
func DownloadFirstNBytes(url string, byteCount int64) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	rangeHeader := fmt.Sprintf("bytes=0-%d", byteCount-1)
	req.Header.Add("Range", rangeHeader)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPartialContent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	} else if resp.StatusCode == http.StatusOK {
		// fmt.Println("Server doesn't support partial content requests, using fallback method")
		buf := make([]byte, byteCount)
		_, err = io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return buf, nil
	}

	return nil, fmt.Errorf("server returned non-OK status, got %d", resp.StatusCode)
}
