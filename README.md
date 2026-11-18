# GoSSLyze
Go wrapper for the SSLyze security scanning tool. Supports SSLyze 6.3.x only (latest release), output of other versions is rejected in order to ensure results are parsed correctly.


# Requirements
GoSSLyze needs **SSLyze 6.3.x**, either as the frozen Windows executable or as a Python package.
* **Windows executable:** Bundles its own Python, nothing else has to be installed.
* **Python package:** `pip install sslyze==6.3.1`. SSLyze 6.3 requires **Python 3.10 or newer** (3.10 to 3.14 are
  declared as supported). pip refuses to install it on older Python versions.

Call `gosslyze.CheckVersion()` once before scanning. It runs `--help` and returns an error if the installed SSLyze
version is not compatible, so a scan does not run just to fail while parsing its result.

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
		command = "python3" // Use SSLyze as a Python module, Python 3.10 or newer
		args = []string{"-m", "sslyze"}
	}

	// Check whether the installed SSLyze version is supported
	errVersion := gosslyze.CheckVersion(command, args...)
	if errVersion != nil {
		return
	}

	// Create new scanner
	s := gosslyze.NewScanner(command, args...)

	// Set the target
	s.WithTarget("localhost", 443)

	// Set scanner flags
	s.WithSslV3()
	s.WithSslV2()
	s.WithTlsV1()
	s.WithTlsV1_1()
	s.WithTlsV1_2()
	s.WithTlsV1_3()
	s.WithEms()            // Check for TLS Extended Master Secret extension support.
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
	s.WithMozillaConfig("intermediate")  // Specify the recommended Mozilla's config to be check against
	// s.WithCustomTlsConfig("tls_config.json") // Alternatively, check against a custom config (not combinable with Mozilla's)
	s.WithQuiet()          // Does not output anything to stdout; useful when using --json_out.

	// Launch
	s.Run()
}
```
