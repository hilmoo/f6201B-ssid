package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func getEnv(key string, defaultValue *string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	if defaultValue == nil {
		panic(fmt.Sprintf("Environment variable %s is required but not set", key))
	}
	return *defaultValue
}

func loadEnvFile() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %v", err)
	}

	file, err := os.Open(cwd + "/.env")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)

		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

func stringPtr(s string) *string {
	return &s
}
