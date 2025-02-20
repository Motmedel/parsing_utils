package errors

import "errors"

var (
	ErrNilGrammar = errors.New("nil grammar")
	ErrEmptyData  = errors.New("empty data")
)
