package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestFormatDateTimeForConsole(t *testing.T) {
	// Use a fixed time to verify format
	ts := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	result := formatDateTimeForConsole(ts)

	// Should contain a date string regardless of timezone
	if !strings.Contains(result, "2024") {
		t.Errorf("expected year in output, got %q", result)
	}
	if !strings.Contains(result, "UTC") {
		t.Errorf("expected UTC offset in output, got %q", result)
	}
}

func TestFormatLastActivity_Nil(t *testing.T) {
	result := formatLastActivity(nil)
	if result != "No recent activity" {
		t.Errorf("expected 'No recent activity', got %q", result)
	}
}

func TestFormatLastActivity_JustNow(t *testing.T) {
	now := time.Now()
	result := formatLastActivity(&now)
	if result != "just now" {
		t.Errorf("expected 'just now', got %q", result)
	}
}

func TestFormatLastActivity_MinutesAgo(t *testing.T) {
	t1 := time.Now().Add(-1 * time.Minute)
	if r := formatLastActivity(&t1); r != "1 minute ago" {
		t.Errorf("expected '1 minute ago', got %q", r)
	}

	t5 := time.Now().Add(-5 * time.Minute)
	if r := formatLastActivity(&t5); r != "5 minutes ago" {
		t.Errorf("expected '5 minutes ago', got %q", r)
	}
}

func TestFormatLastActivity_HoursAgo(t *testing.T) {
	t1 := time.Now().Add(-1 * time.Hour)
	if r := formatLastActivity(&t1); r != "1 hour ago" {
		t.Errorf("expected '1 hour ago', got %q", r)
	}

	t3 := time.Now().Add(-3 * time.Hour)
	if r := formatLastActivity(&t3); r != "3 hours ago" {
		t.Errorf("expected '3 hours ago', got %q", r)
	}
}

func TestFormatLastActivity_DaysAgo(t *testing.T) {
	t1 := time.Now().Add(-24 * time.Hour)
	if r := formatLastActivity(&t1); r != "1 day ago" {
		t.Errorf("expected '1 day ago', got %q", r)
	}

	t7 := time.Now().Add(-7 * 24 * time.Hour)
	if r := formatLastActivity(&t7); r != "7 days ago" {
		t.Errorf("expected '7 days ago', got %q", r)
	}
}

func TestFormatSessionDuration_ExactHours(t *testing.T) {
	if r := formatSessionDuration(3600); r != "1 hour" {
		t.Errorf("expected '1 hour', got %q", r)
	}
	if r := formatSessionDuration(7200); r != "2 hours" {
		t.Errorf("expected '2 hours', got %q", r)
	}
}

func TestFormatSessionDuration_Minutes(t *testing.T) {
	if r := formatSessionDuration(60); r != "1 minute" {
		t.Errorf("expected '1 minute', got %q", r)
	}
	if r := formatSessionDuration(300); r != "5 minutes" {
		t.Errorf("expected '5 minutes', got %q", r)
	}
	// Non-exact hour boundary
	if r := formatSessionDuration(3660); r != "61 minutes" {
		t.Errorf("expected '61 minutes', got %q", r)
	}
}

func TestIndentBlock(t *testing.T) {
	result := indentBlock("line1\nline2\nline3", "  ")
	expected := "  line1\n  line2\n  line3"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestIndentBlock_EmptyLines(t *testing.T) {
	result := indentBlock("line1\n\nline3", ">> ")
	if !strings.Contains(result, ">> line1") {
		t.Error("expected indented line1")
	}
	if !strings.Contains(result, ">> line3") {
		t.Error("expected indented line3")
	}
	// Empty line should NOT be indented
	lines := strings.Split(result, "\n")
	if lines[1] != "" {
		t.Errorf("expected empty line preserved, got %q", lines[1])
	}
}

func TestIndentBlock_SingleLine(t *testing.T) {
	result := indentBlock("hello", "  ")
	if result != "  hello" {
		t.Errorf("expected '  hello', got %q", result)
	}
}

func TestIndentBlock_Empty(t *testing.T) {
	result := indentBlock("", "  ")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}
