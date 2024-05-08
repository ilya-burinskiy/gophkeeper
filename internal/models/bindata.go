package models

import (
	"bytes"
	"encoding/gob"
)

type BinData struct {
	ID       int
	Filename string
	Bytes    []byte
}

func (bin *BinData) Marshall() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(bin)

	return buf.Bytes(), err
}

func (bin *BinData) Unmarshall(bs []byte) error {
	buf := bytes.NewBuffer(bs)
	decoder := gob.NewDecoder(buf)

	return decoder.Decode(bin)
}
