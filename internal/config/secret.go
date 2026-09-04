package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// minPepperBytes is the minimum accepted length of the cache pepper.
//
// The pepper keys the HMAC that derives cache keys from credentials. Below the
// hash's block-relevant length it stops being a meaningful secret, and a
// leaked cache would become crackable offline at the cost of the password
// alone. `openssl rand -hex 32` produces 64 characters and passes.
const minPepperBytes = 32

// maxSecretBytes bounds how much a secret file may contain. A secret this
// large is a wrong path — a certificate, a log, a whole configuration file —
// and reading it into memory silently would hide the mistake.
const maxSecretBytes = 64 * 1024

// loadSecrets reads every file the configuration references. It runs before
// validation so that a directory whose password file is missing is reported as
// such, rather than as a directory that happens to have an empty password.
func (c *Config) loadSecrets() (warnings []string, err error) {
	var problems []error

	if c.Cache.Enabled && c.Cache.PepperFile != "" {
		pepper, warning, err := readSecretFile(c.Cache.PepperFile)
		switch {
		case err != nil:
			problems = append(problems, fmt.Errorf("cache.pepper_file: %w", err))
		case len(pepper) < minPepperBytes:
			problems = append(problems, fmt.Errorf(
				"cache.pepper_file: %s holds %d bytes, at least %d are required; generate it with: openssl rand -hex 32",
				c.Cache.PepperFile, len(pepper), minPepperBytes))
		default:
			c.Cache.Pepper = pepper
		}

		if warning != "" {
			warnings = append(warnings, "cache.pepper_file: "+warning)
		}
	}

	for _, name := range sortedKeys(c.LDAP) {
		dir := c.LDAP[name]

		if dir.BindPasswordFile != "" {
			password, warning, err := readSecretFile(dir.BindPasswordFile)
			if err != nil {
				problems = append(problems, fmt.Errorf("ldap.%s.bind_password_file: %w", name, err))
			} else {
				dir.BindPassword = string(password)
			}

			if warning != "" {
				warnings = append(warnings, fmt.Sprintf("ldap.%s.bind_password_file: %s", name, warning))
			}
		}

		if dir.TLS.CAFile != "" {
			pem, err := os.ReadFile(dir.TLS.CAFile)
			if err != nil {
				problems = append(problems, fmt.Errorf("ldap.%s.tls.ca_file: %w", name, err))
			} else {
				dir.TLS.CACertificates = pem
			}
		}
	}

	if len(problems) > 0 {
		return warnings, fmt.Errorf("configuration secrets:\n%s", indentErrors(problems))
	}

	return warnings, nil
}

// readSecretFile reads a single-value secret file.
//
// Trailing whitespace is stripped, because every editor and every `echo` adds a
// newline and a password that silently includes one is a support case nobody
// enjoys. Interior whitespace is preserved: it may be part of the secret.
func readSecretFile(path string) (secret []byte, warning string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("%s does not exist", path)
		}

		return nil, "", err
	}

	if info.IsDir() {
		return nil, "", fmt.Errorf("%s is a directory", path)
	}

	if info.Size() > maxSecretBytes {
		return nil, "", fmt.Errorf("%s is %d bytes, which is too large for a secret file", path, info.Size())
	}

	// The path comes from the configuration file, which is itself trusted:
	// anyone who can change it can already run whatever they like as this
	// user.
	raw, err := os.ReadFile(path) //nolint:gosec // secret paths are configuration, not request input
	if err != nil {
		return nil, "", err
	}

	// Reported rather than refused: a wrong mode on a running system should
	// be loud, but it must not turn the next routine restart into an outage.
	if mode := info.Mode().Perm(); mode&0o044 != 0 {
		warning = fmt.Sprintf("%s is readable beyond its owner and group (mode %04o); restrict it with: chmod 0640 %s",
			path, mode, path)
	}

	secret = []byte(strings.TrimRight(string(raw), " \t\r\n"))

	if len(secret) == 0 {
		return nil, warning, fmt.Errorf("%s is empty", path)
	}

	return secret, warning, nil
}
