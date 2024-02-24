
# identifybin

A small package used to identify the OS and Architecture of a binary from a few bytes of a file, made as a support package for github.com/earentir/gitearelease


## Usage/Examples

### Check version of current and compare to latest release
```go
import (
	"fmt"

	"github.com/earentir/identifybin"
)

func checkVersion() {
	// Get OS of attachment binary
	url := "https://github.com/earentir/subscan/releases/download/v0.1.5/subscan"
	byteCount := int64(256) // number of bytes to download

	bytes, err := identifybin.DownloadFirstNBytes(url, byteCount)
	if err != nil {
	fmt.Println("Error:", err)
	break
	}

	binType, err := identifybin.DetectOSAndArch(bytes)
	if err != nil {
	fmt.Println("Error:", err)
	break
	}

	fmt.Printf("%s %s %s\n", binType.OperatingSystem, binType.Arch, binType.Endianess)
}
```

## Func Reference

### DetectOSAndArch
```go
func DetectOSAndArch(input interface{}) (BinaryType, error)
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `input` | `string` or `[]byte`  | **Required**  |

DetectOSAndArch will either take a byte array or a string and then detect the OS and Architecture of that file


### DownloadFirstNBytes
```go
func DownloadFirstNBytes(url string, byteCount int64) ([]byte, error)
```
| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `url` | `string` | **Required**  |
| `byteCount` | `int64` | **Required**  |

DownloadFirstNBytes downloads the first N bytes of a file from a URL.

## Dependancies & Documentation
[![Go Mod](https://img.shields.io/github/go-mod/go-version/earentir/identifybin)]()

[![Go Reference](https://pkg.go.dev/badge/github.com/earentir/identifybin.svg)](https://pkg.go.dev/github.com/earentir/identifybin) 

[![Dependancies](https://img.shields.io/librariesio/github/earentir/identifybin)]()

## Authors
- [@earentir](https://www.github.com/earentir)


## License
I will always follow the Linux Kernel License as primary, if you require any other OPEN license please let me know and I will try to accomodate it.

[![License](https://img.shields.io/github/license/earentir/identifybin)](https://opensource.org/license/gpl-2-0)
