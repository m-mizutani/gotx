package gotx

import "github.com/m-mizutani/goerr"

var (
	ErrRequestFailed = goerr.New("OTX API request is failed")
)
