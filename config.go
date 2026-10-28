package ssid

import (
	"io"
	"net/http"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

// Config holds the router address and credentials used by Login.
type Config struct {
	RouterURL string
	Username  string
	Password  string
}

func routerRequest(client *http.Client, method, target string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
