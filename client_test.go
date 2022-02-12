package gotx_test

import (
	"context"
	"os"
	"testing"

	"github.com/m-mizutani/gotx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientAccess(t *testing.T) {
	apiKey := os.Getenv("OTX_API_KEY")
	if apiKey == "" {
		t.Skip("OTX_API_KEY is not set")
	}

	client, err := gotx.New(apiKey)
	require.NoError(t, err)
	output, err := client.GetIPv4Malware(context.Background(), &gotx.GetIPv4Request{
		IPAddr: "91.240.118.172",
	})
	require.NoError(t, err)
	assert.NotNil(t, output)
}
