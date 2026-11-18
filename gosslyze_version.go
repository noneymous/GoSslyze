package gosslyze

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CheckVersion executes SSLyze with '--help' and verifies that its version is supported by this wrapper. The command is
// given the same way as to NewScanner, e.g. the path of the SSLyze executable or the Python interpreter with the
// arguments '-m' and 'sslyze'. Call it before scanning to ensure output can be parsed correctly.
func CheckVersion(sslyzePath string, sslyzeArgs ...string) error {

	// Execute SSLyze to retrieve the help message, which contains the version
	var stdout, stderr bytes.Buffer
	args := append(append([]string{}, sslyzeArgs...), "--help")
	cmd := exec.Command(sslyzePath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	errCmd := cmd.Run()
	if errCmd != nil {
		return fmt.Errorf("could not execute '%s %v': %w: %s", sslyzePath, args, errCmd, stderr.String())
	}

	// Extract the version from the help message
	version, errVersion := parseVersion(stdout.String())
	if errVersion != nil {
		return errVersion
	}

	// Return the verification result of the extracted version
	return verifyVersion(version)
}

// parseVersion extracts the SSLyze version from the help message, which contains a line like 'SSLyze version 6.3.1'.
func parseVersion(msgHelp string) (string, error) {

	// Locate the version in the help message
	const prefix = "SSLyze version "
	index := strings.Index(msgHelp, prefix)
	if index == -1 {
		return "", fmt.Errorf("could not extract SSLyze version from help message, please install version '%s.x'", SupportedSslyzeVersion)
	}

	// Return the first word following the prefix
	fields := strings.Fields(msgHelp[index+len(prefix):])
	if len(fields) == 0 {
		return "", fmt.Errorf("could not extract SSLyze version from help message, please install version '%s.x'", SupportedSslyzeVersion)
	}
	return fields[0], nil
}

// verifyVersion returns an error if the given SSLyze version is not supported by this wrapper.
func verifyVersion(version string) error {

	// Only accept patch releases of the supported major and minor version
	if !strings.HasPrefix(version, SupportedSslyzeVersion+".") {
		return fmt.Errorf("SSLyze version '%s' is not compatible, please install version '%s.x'", version, SupportedSslyzeVersion)
	}

	// Return nil as everything went fine
	return nil
}
