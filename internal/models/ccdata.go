package models

import (
	"bytes"
	"encoding/gob"
	"time"
)

type CreditCard struct {
	Description string
	Number      string
	Name        string
	ExpiryDate  time.Time
	CVV2        string
}

func (cc *CreditCard) Marshall() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(cc)

	return buf.Bytes(), err
}

func (cc *CreditCard) Unmarshall(b []byte) error {
	buf := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buf)

	return decoder.Decode(cc)
}
