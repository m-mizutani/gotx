package gotx_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/m-mizutani/gotx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClient struct {
	code  int
	fpath string
	hook  func(*http.Request)
}

func (x *testClient) Do(req *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
	}
	if x.code != 0 {
		resp.StatusCode = x.code
	}
	if x.fpath != "" {
		raw, err := os.ReadFile(x.fpath)
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
	}

	return resp, nil
}

func TestGetIPv4General(t *testing.T) {
	tc := &testClient{
		fpath: "./testdata/indicator_ip/general.json",
		hook: func(r *http.Request) {
			assert.Equal(t, "xxx", r.Header.Get("X-OTX-API-KEY"))
		},
	}
	client, err := gotx.New("xxx", gotx.WithHTTPClient(tc))
	require.NoError(t, err)
	resp, err := client.GetIPv4General(context.Background(), &gotx.GetIPv4Request{
		IPAddr: "10.1.2.3",
	})
	require.NoError(t, err)
	require.Equal(t, "http://whois.domaintools.com/91.240.118.172", resp.Whois)
}

func TestGetIPv4Geo(t *testing.T) {
	tc := &testClient{
		fpath: "./testdata/indicator_ip/geo.json",
	}
	client, err := gotx.New("xxx", gotx.WithHTTPClient(tc))
	require.NoError(t, err)
	resp, err := client.GetIPv4Geo(context.Background(), &gotx.GetIPv4Request{
		IPAddr: "10.1.2.3",
	})
	require.NoError(t, err)
	require.Equal(t, "EU", resp.ContinentCode)
}

func TestGetIPv4Malware(t *testing.T) {
	tc := &testClient{
		fpath: "./testdata/indicator_ip/malware.json",
	}
	client, err := gotx.New("xxx", gotx.WithHTTPClient(tc))
	require.NoError(t, err)
	resp, err := client.GetIPv4Malware(context.Background(), &gotx.GetIPv4Request{
		IPAddr: "10.1.2.3",
	})
	require.NoError(t, err)
	require.Len(t, resp.Data, 10)
}
