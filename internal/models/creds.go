package models

import (
	"bytes"
	"encoding/gob"
)

type Credentials struct {
	ID          int
	Description string
	Login       string
	Password    string
}

func (creds *Credentials) Marshall() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(creds)

	return buf.Bytes(), err
}

func (creds *Credentials) Unmarshall(b []byte) error {
	buf := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buf)

	return decoder.Decode(creds)
}
