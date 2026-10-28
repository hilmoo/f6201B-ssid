package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	ssid "github.com/hilmoo/f6201B-ssid"
)

type Config struct {
	ssid.Config
	Wlan1Index string
	Wlan2Index string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: Missing required argument.")
		fmt.Printf("Usage: %s <true|false>\n", filepath.Base(os.Args[0]))
		return
	}

	enable, err := strconv.ParseBool(os.Args[1])
	if err != nil {
		fmt.Printf("Error: Invalid argument '%s'. Please provide 'true' or 'false'.\n", os.Args[1])
		return
	}

	if err := loadEnvFile(); err != nil {
		fmt.Printf("Note: %v\n", err)
	}

	config := Config{
		Config: ssid.Config{
			RouterURL: getEnv("ROUTER_URL", nil),
			Username:  getEnv("ROUTER_USERNAME", nil),
			Password:  getEnv("ROUTER_PASSWORD", nil),
		},
		Wlan1Index: getEnv("WLAN1_INDEX", stringPtr("1")),
		Wlan2Index: getEnv("WLAN2_INDEX", stringPtr("5")),
	}

	wlan1, err := strconv.Atoi(config.Wlan1Index)
	if err != nil {
		fmt.Printf("Error: Invalid WLAN1_INDEX '%s'. Must be an integer.\n", config.Wlan1Index)
		return
	}
	wlan2, err := strconv.Atoi(config.Wlan2Index)
	if err != nil {
		fmt.Printf("Error: Invalid WLAN2_INDEX '%s'. Must be an integer.\n", config.Wlan2Index)
		return
	}

	client, err := ssid.Login(config.Config)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}
	fmt.Println("Login successful, cookie acquired!")

	if err := ssid.ToggleSSIDs(client, config.RouterURL, enable, wlan1, wlan2); err != nil {
		fmt.Printf("Failed to toggle SSID: %v\n", err)
		return
	}

	state := "disabled"
	if enable {
		state = "enabled"
	}
	fmt.Printf("SSID%d and SSID%d %s\n", wlan1, wlan2, state)
}
