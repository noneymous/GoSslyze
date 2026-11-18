package gosslyze

import "testing"

// TestParseVersion verifies that the version is extracted from SSLyze's help message.
func TestParseVersion(t *testing.T) {

	tests := []struct {
		name            string
		msgHelp         string
		expectedVersion string
		wantErr         bool
	}{
		{
			name:            "Help message",
			msgHelp:         "usage: sslyze [-h]\n\nSSLyze version 6.3.1\n\npositional arguments:\n  target\n",
			expectedVersion: "6.3.1",
		},
		{
			name:            "Version at the end without line break",
			msgHelp:         "SSLyze version 6.3.1",
			expectedVersion: "6.3.1",
		},
		{
			name:    "No version",
			msgHelp: "usage: sslyze [-h]\n",
			wantErr: true,
		},
		{
			name:    "Prefix without version",
			msgHelp: "SSLyze version ",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Extract version
			version, errVersion := parseVersion(tt.msgHelp)
			if (errVersion != nil) != tt.wantErr {
				t.Fatalf("parseVersion() error = %v, wantErr %v", errVersion, tt.wantErr)
			}
			if version != tt.expectedVersion {
				t.Errorf("version = %q, want %q", version, tt.expectedVersion)
			}
		})
	}
}

// TestCheckVersion_NotExecutable verifies that an error is returned if SSLyze cannot be executed.
func TestCheckVersion_NotExecutable(t *testing.T) {

	// Check a command that does not exist
	errVersion := CheckVersion("./does-not-exist/sslyze")
	if errVersion == nil {
		t.Errorf("expected an error for a missing executable")
	}
}
