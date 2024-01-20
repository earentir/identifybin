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

const (
	elfMagic    = "\x7FELF"
	machOMagic  = "\xFE\xED\xFA"
	peMagic     = "\x4D\x5A"
	machO64Mask = "\xCF\xFA\xED\xFE"
)

func DetectOSAndArch(input interface{}) (string, string, error) {
	var b []byte
	var err error

	switch v := input.(type) {
	case string:
		b, err = os.ReadFile(v)
		if err != nil {
			return "", "", err
		}
	case []byte:
		b = v
	default:
		return "", "", errors.New("unsupported input type")
	}

	return detectOSAndArchFromBytes(b)
}

func detectOSAndArchFromBytes(b []byte) (string, string, error) {
	if len(b) < 64 {
		return "", "", errors.New("binary too small")
	}

	switch {
	case bytes.HasPrefix(b, []byte(elfMagic)):
		return parseELF(b)
	case bytes.HasPrefix(b, []byte{0xFE, 0xED, 0xFA, 0xCE}) || bytes.HasPrefix(b, []byte{0xFE, 0xED, 0xFA, 0xCF}) || bytes.HasPrefix(b, []byte{0xCE, 0xFA, 0xED, 0xFE}) || bytes.HasPrefix(b, []byte{0xCF, 0xFA, 0xED, 0xFE}):
		return parseMachO(b)
	case bytes.HasPrefix(b, []byte(peMagic)):
		return parsePE(b)
	default:
		return "", "", errors.New("unknown binary format")
	}
}

func parseELF(b []byte) (string, string, error) {
	operatingSystem := "linux"
	var arch string
	machine := b[18]

	switch machine {
	case 0x03:
		arch = "x86"
	case 0x3E:
		arch = "x86_64"
	case 0xB7:
		arch = "arm64"
	case 0x28:
		arch = "arm"
	default:
		return "", "", errors.New("unsupported ELF architecture")
	}

	return operatingSystem, arch, nil
}

func parseMachO(b []byte) (string, string, error) {
	operatingSystem := "darwin"
	var arch string
	var magic uint32
	buf := bytes.NewReader(b)

	err := binary.Read(buf, binary.BigEndian, &magic)
	if err != nil {
		return "", "", err
	}

	isLE := (magic == 0xCAFEBABE) || (magic == 0xCAFED00D)
	var byteOrder binary.ByteOrder
	if isLE {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}

	var cputype int32
	if (magic == 0xFEEDFACE) || (magic == 0xFEEDFACF) {
		err = binary.Read(buf, byteOrder, &cputype)
	} else {
		buf.Seek(8, 0)
		err = binary.Read(buf, byteOrder, &cputype)
	}
	if err != nil {
		return "", "", err
	}

	switch cputype {
	case 7:
		arch = "x86"
	case 0x01000007, 0x3000000:
		arch = "x86_64"
	case 12:
		arch = "arm"
	case 0x0100000C, 0x0100000D, 0x0:
		arch = "arm64"
	default:
		return "", "", fmt.Errorf("unsupported Mach-O architecture: 0x%x", cputype)
	}

	return operatingSystem, arch, nil
}

func parsePE(b []byte) (string, string, error) {
	operatingSystem := "windows"
	var arch string

	// PE header offset
	peOffset := binary.LittleEndian.Uint32(b[0x3C:])
	machine := binary.LittleEndian.Uint16(b[peOffset+4:])

	switch machine {
	case 0x014C:
		arch = "x86"
	case 0x8664:
		arch = "x86_64"
	case 0xAA64:
		arch = "arm64"
	default:
		return "", "", errors.New("unsupported PE architecture")
	}

	return operatingSystem, arch, nil
}

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
		fmt.Println("Server doesn't support partial content requests, using fallback method")
		buf := make([]byte, byteCount)
		_, err = io.ReadFull(resp.Body, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return buf, nil
	} else {
		return nil, fmt.Errorf("server returned non-OK status, got %d", resp.StatusCode)
	}
}
