package models

type BinData struct {
	Bytes []byte
}

func (bin *BinData) Marshall() ([]byte, error) {
	return bin.Bytes, nil
}

func (bin *BinData) Unmarshall(bs []byte) error {
	bin.Bytes = bs
	return nil
}
