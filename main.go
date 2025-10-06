package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func loadPatternsFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as JSON first
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err == nil {
		return patterns, nil
	}

	// If JSON parsing fails, try line-by-line text format
	patterns = []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	if len(patterns) == 0 {
		return nil, fmt.Errorf("no patterns found in file")
	}

	return patterns, nil
}

func matchesAnyPattern(action string, patterns []string) (bool, []string) {
	var matches []string
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, action)
		if err != nil {
			continue
		}
		if matched {
			matches = append(matches, pattern)
		}
	}
	return len(matches) > 0, matches
}

func main() {
	configFile := flag.String("config", "pb.json", "Path to the patterns config file (JSON or text format)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <action>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample: %s -config pb.json ec2:RunInstances\n", os.Args[0])
		os.Exit(1)
	}

	action := flag.Arg(0)

	// Load patterns from config file
	patterns, err := loadPatternsFromFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading patterns: %v\n", err)
		os.Exit(1)
	}

	matched, matchingPatterns := matchesAnyPattern(action, patterns)

	if matched {
		fmt.Printf("✓ '%s' matches the following pattern(s):\n", action)
		for _, pattern := range matchingPatterns {
			fmt.Printf("  - %s\n", pattern)
		}
		os.Exit(0)
	} else {
		fmt.Printf("✗ '%s' does not match any pattern\n", action)
		os.Exit(1)
	}
}
