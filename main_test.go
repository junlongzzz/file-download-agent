package main

import "testing"

func TestParseBoolValue(t *testing.T) {
	truthy := []string{"1", "t", "true", "TRUE", "True", "yes", "on", "enable", "enabled"}
	for _, value := range truthy {
		got, ok := parseBoolValue(value)
		if !ok || !got {
			t.Errorf("parseBoolValue(%q) = (%v, %v), want (true, true)", value, got, ok)
		}
	}

	falsy := []string{"0", "f", "false", "FALSE", "False", "no", "off", "disable", "disabled"}
	for _, value := range falsy {
		got, ok := parseBoolValue(value)
		if !ok || got {
			t.Errorf("parseBoolValue(%q) = (%v, %v), want (false, true)", value, got, ok)
		}
	}

	for _, value := range []string{"", "maybe", "tru"} {
		if got, ok := parseBoolValue(value); ok {
			t.Errorf("parseBoolValue(%q) = (%v, true), want ok=false", value, got)
		}
	}
}
