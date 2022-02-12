package gotx

import (
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/m-mizutani/goerr"
)

func WithHTTPClient(httpClient HTTPClient) Option {
	return func(client *Client) error {
		client.httpClient = httpClient
		return nil
	}
}

func WithBaseURL(url string) Option {
	return func(client *Client) error {
		if err := validation.Validate(url, validation.Required, is.URL); err != nil {
			return goerr.Wrap(err)
		}
		client.baseURL = strings.TrimRight(url, "/")
		return nil
	}
}
