# identifybin

Example:

```go
url := "https://yoururltoafilehere"
byteCount := int64(256) //number of bytes to download
bytes, err := idbin.DownloadFirstNBytes(url, byteCount)
if err != nil {
    fmt.Println("Error:", err)
    return
}
fmt.Printf("Downloaded %d bytes: %v\n", len(bytes), bytes)

// operatingSystem, arch, err := detectOSAndArch(os.Args[1]) //You can directly pass a file path to detectOSAndArch
   operatingSystem, arch, err := idbin.DetectOSAndArch(bytes) //Or you can pass the bytes of a file
if err != nil {
	fmt.Println("Error:", err)
       	return
}
fmt.Printf("Operating System: %s\nArch: %s\n", operatingSystem, arch)
```
