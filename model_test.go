package gosslyze

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestUtcTime_UnmarshalJSON(t *testing.T) {
	type fields struct {
		String string
		Time   time.Time
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Without timezone",
			data:    []byte("2024-07-31T10:36:00"),
			wantErr: false,
		},
		{
			name:    "With timezone",
			data:    []byte("2024-07-31T10:36:00Z"),
			wantErr: false,
		},
		{
			name:    "With timezone and milliseconds",
			data:    []byte("2024-07-31T10:36:00.8111Z"),
			wantErr: false,
		},
		{
			name:    "With timezone and milliseconds short",
			data:    []byte("2024-07-31T10:36:00.8Z"),
			wantErr: false,
		},
		{
			name:    "With full details",
			data:    []byte("2024-07-31T10:36:00.8111-02:00"),
			wantErr: false,
		},
		{
			name:    "With full details milliseconds short",
			data:    []byte("2024-07-31T10:36:00.8-02:00"),
			wantErr: false,
		},
		{
			name:    "Invalid 1",
			data:    []byte("2024-07 10:36:00"),
			wantErr: true,
		},
		{
			name:    "Invalid 2",
			data:    []byte("2024-07T10:36:00.8111Z"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ut := &UtcTime{}
			fmt.Println(string(tt.data))
			if err := ut.UnmarshalJSON(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Println(ut.Time)
			fmt.Println()
		})
	}
}

func TestPathValidationUnmarshalJSON(t *testing.T) {
	// Define test cases
	tests := []struct {
		name     string
		input    string
		expected PathValidation
		wantErr  bool
	}{
		{
			name: "Old format with openssl_error_string",
			input: `{
                "openssl_error_string": "SSL error occurred",
                "trust_store": {
                    "path": "/path/to/store",
                    "name": "Mozilla",
                    "version": "2023",
                    "ev_oids": null
                },
                "verified_certificate_chain": null,
                "was_validation_successful": false
            }`,
			expected: PathValidation{
				ValidationError: "SSL error occurred",
				OpenSslError:    "SSL error occurred",
				TrustStore: TrustStore{
					Path:    "/path/to/store",
					Name:    "Mozilla",
					Version: "2023",
					EvOids:  nil,
				},
				VerifiedChain:        nil,
				ValidationSuccessful: false,
			},
			wantErr: false,
		},
		{
			name: "New Format with validation_error",
			input: `{
                "validation_error": "Validation failed",
                "trust_store": {
                    "path": "/path/to/store",
                    "name": "Mozilla",
                    "version": "2023",
                    "ev_oids": null
                },
                "verified_certificate_chain": null,
                "was_validation_successful": false
            }`,
			expected: PathValidation{
				ValidationError: "Validation failed",
				OpenSslError:    "",
				TrustStore: TrustStore{
					Path:    "/path/to/store",
					Name:    "Mozilla",
					Version: "2023",
					EvOids:  nil,
				},
				VerifiedChain:        nil,
				ValidationSuccessful: false,
			},
			wantErr: false,
		},
	}

	// Run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got PathValidation
			err := json.Unmarshal([]byte(tt.input), &got)

			// Check error cases
			if (err != nil) != tt.wantErr {
				t.Errorf("PathValidation.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check ValidationError field
			if got.ValidationError != tt.expected.ValidationError {
				t.Errorf("ValidationError = %v, want %v", got.ValidationError, tt.expected.ValidationError)
			}

			// Check openSslError field
			if got.OpenSslError != tt.expected.OpenSslError {
				t.Errorf("openSslError = %v, want %v", got.OpenSslError, tt.expected.OpenSslError)
			}
		})
	}
}
