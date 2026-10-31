//go:build !with_naive

package outbound

import "errors"

type Naive struct {
	*Base
}

func NewNaive(NaiveOption) (*Naive, error) {
	return nil, errors.New("naive support is not included; rebuild with the with_naive tag and a matching Cronet library")
}
