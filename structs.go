package identifybin

const (
	elfMagic    = "\x7FELF"
	machOMagic  = "\xFE\xED\xFA"
	peMagic     = "\x4D\x5A"
	machO64Mask = "\xCF\xFA\xED\xFE"
)

// BinaryType is the type of binary
type BinaryType struct {
	operatingSystem string
	arch            string
	endianess       string
}
