package identifybin

const (
	elfMagic    = "\x7FELF"
	machOMagic  = "\xFE\xED\xFA"
	peMagic     = "\x4D\x5A"
	machO64Mask = "\xCF\xFA\xED\xFE"
)

// BinaryType is the type of binary
type BinaryType struct {
	OperatingSystem string
	Arch            string
	Endianess       string
}
