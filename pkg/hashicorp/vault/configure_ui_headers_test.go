// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
		wantErr  bool
	}{
		{
			name:  "JSON format",
			input: `{"X-Environment":"Production","X-Cluster":"us-east-1"}`,
			expected: map[string]string{
				"X-Environment": "Production",
				"X-Cluster":     "us-east-1",
			},
			wantErr: false,
		},
		{
			name:  "Key=value format",
			input: "X-Environment=Production,X-Cluster=us-east-1",
			expected: map[string]string{
				"X-Environment": "Production",
				"X-Cluster":     "us-east-1",
			},
			wantErr: false,
		},
		{
			name:  "Key=value with spaces",
			input: " X-Environment = Production , X-Cluster = us-east-1 ",
			expected: map[string]string{
				"X-Environment": "Production",
				"X-Cluster":     "us-east-1",
			},
			wantErr: false,
		},
		{
			name:     "Empty JSON",
			input:    "{}",
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name:    "Invalid key=value format",
			input:   "X-Environment-Production",
			wantErr: true,
		},
		{
			name:    "Empty key",
			input:   "=Production",
			wantErr: true,
		},
		{
			name:  "JSON with quoted values containing commas",
			input: `{"X-Environment":"Production,Staging","X-Cluster":"us-east-1"}`,
			expected: map[string]string{
				"X-Environment": "Production,Staging",
				"X-Cluster":     "us-east-1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHeaders(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(result) != len(tt.expected) {
					t.Errorf("parseHeaders() result length = %v, expected length %v", len(result), len(tt.expected))
					return
				}

				for key, expectedValue := range tt.expected {
					if actualValue, exists := result[key]; !exists || actualValue != expectedValue {
						t.Errorf("parseHeaders() result[%s] = %v, expected %v", key, actualValue, expectedValue)
					}
				}
			}
		})
	}
}

func TestParseJSONPairs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:  "Simple pairs",
			input: `"key1":"value1","key2":"value2"`,
			expected: []string{
				`"key1":"value1"`,
				`"key2":"value2"`,
			},
		},
		{
			name:  "Value with comma",
			input: `"key1":"value1,extra","key2":"value2"`,
			expected: []string{
				`"key1":"value1,extra"`,
				`"key2":"value2"`,
			},
		},
		{
			name:     "Empty content",
			input:    "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseJSONPairs(tt.input)

			if len(result) != len(tt.expected) {
				t.Errorf("parseJSONPairs() result length = %v, expected length %v", len(result), len(tt.expected))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("parseJSONPairs() result[%d] = %v, expected %v", i, result[i], expected)
				}
			}
		})
	}
}

func TestParseJSONPair(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedKey string
		expectedVal string
		wantErr     bool
	}{
		{
			name:        "Valid pair",
			input:       `"X-Environment":"Production"`,
			expectedKey: "X-Environment",
			expectedVal: "Production",
			wantErr:     false,
		},
		{
			name:        "Unquoted value",
			input:       `"X-Environment":Production`,
			expectedKey: "X-Environment",
			expectedVal: "Production",
			wantErr:     false,
		},
		{
			name:    "Unquoted key",
			input:   `X-Environment:"Production"`,
			wantErr: true,
		},
		{
			name:    "Missing colon",
			input:   `"X-Environment""Production"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, err := parseJSONPair(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseJSONPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if key != tt.expectedKey {
					t.Errorf("parseJSONPair() key = %v, expected %v", key, tt.expectedKey)
				}
				if value != tt.expectedVal {
					t.Errorf("parseJSONPair() value = %v, expected %v", value, tt.expectedVal)
				}
			}
		})
	}
}
