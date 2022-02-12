package main

import (
	"context"
	"fmt"
	"os"

	"github.com/m-mizutani/gotx"
)

func main() {
	client, err := gotx.New(os.Getenv("OTX_API_KEY"))
	if err != nil {
		panic(err.Error())
	}

	req := &gotx.GetIPv4Request{
		IPAddr: "91.240.118.172",
	}
	resp, err := client.GetIPv4Malware(context.Background(), req)
	if err != nil {
		panic(err.Error())
	}

	for _, data := range resp.Data {
		fmt.Println(data.Hash, "=>", data.Detections)
	}
}
