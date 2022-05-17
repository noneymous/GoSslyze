# GoSSLyze
Go wrapper for the SSLyze security scanning tool.


# Sample use
GoSSLyze can be used on Windows and Linux, but it has to be initialized a bit differently.

```
func sample(){

	// Initialize command depending on whether to use the Windows executable 
	// or SSLyze as a Python module
	var command string
	var args []string
	if runtime.GOOS == "windows" {
		command = "./bin/sslyze.exe" // Use Windows binary
		args = []string{}
	} else {
		command = "python3.10" // Use SSLyze as a Python module
		args = []string{"-m", "sslyze"}
	}

	// Create new scanner
	s := NewScanner(command, args...)

	// Set the target
	s.WithTarget("localhost", 443)

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
	s.WithResumeAttempts(10)
	s.WithCompression()
	s.WithFallback()
	s.WithRobot()
	s.WithCertInfo()       // Validate certificate
	s.WithSni("localhost") // Specify the hostname to connect to using sni.
	s.WithEarlyData()
	s.WithEllipticCurves()
	s.WithMozillaConfig("modern")

	// Launch
	s.Run()
}
```
