package gosslyze

import (
	"runtime"
	"testing"
)

func TestSample(t *testing.T) {

	// Initialize command depending on whether to use the Windows executable or SSLyze as a Python module
	var command string
	var args []string
	if runtime.GOOS == "windows" {
		command = "./bin/sslyze.exe" // Use Windows binary
		args = []string{}
	} else {
		command = "python3.8" // Use SSLyze as a Python module
		args = []string{"-m", "sslyze"}
	}

	// Create new scanner
	s := NewScanner(command, args...)

	// Set the target
	target := "localhost"
	s.WithTarget(target, 443)

	// Set scanner flags
	s.WithSslV3()
	s.WithSslV2()
	s.WithTlsV1()
	s.WithTlsV1_1()
	s.WithTlsV1_2()
	s.WithTlsV1_3()
	s.WithCcs()
	s.WithHeartbleed()
	s.WithRenegotiation()
	s.WithResume()
	s.WithResumeRate()
	s.WithHttpHeaders()
	s.WithCompression()
	s.WithFallback()
	s.WithRobot()
	s.WithCertInfo()  // Validate certificate
	s.WithSni(target) // Specify the hostname to connect to using sni.
	s.WithEarlyData()

	// Launch
	s.Run()
}
