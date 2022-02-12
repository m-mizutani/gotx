package gotx

import "net/http"

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Option func(client *Client) error
