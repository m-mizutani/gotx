package gotx

import (
	"encoding/json"
	"net/http"

	"github.com/m-mizutani/goerr"
	"github.com/m-mizutani/zlog"
)

const apiBaseURL = "https://otx.alienvault.com"

type Client struct {
	apiKey     string
	httpClient HTTPClient
	baseURL    string
	logger     *zlog.Logger
}

func New(apiKey string, options ...Option) (*Client, error) {
	client := &Client{
		baseURL:    apiBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{},
		logger:     zlog.New(),
	}

	for _, opt := range options {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (x *Client) do(req *http.Request, out interface{}) error {
	req.Header.Add("X-OTX-API-KEY", x.apiKey)
	resp, err := x.httpClient.Do(req)
	if err != nil {
		return goerr.Wrap(err, "fail HTTP request")
	}
	if resp.StatusCode != http.StatusOK {
		return ErrRequestFailed.New().With("code", resp.StatusCode).With("url", req.URL.String())
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return goerr.Wrap(err, "fail to parse HTTP response")
	}

	return nil
}
