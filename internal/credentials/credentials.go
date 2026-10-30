// Package credentials resolves the username and password the CLI presents to
// the Breakwater API and registry.
package credentials

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Credentials is a username and password (a customer pull token).
type Credentials struct {
	Username string
	Password string
}

// Options controls Resolve.
type Options struct {
	Username      string
	PasswordStdin bool
	Stdin         io.Reader
	Getenv        func(string) string
	Keychain      authn.Keychain
	RegistryHost  string
}

// Resolve picks credentials in order: --username with --password-stdin, then
// BREAKWATER_USERNAME with BREAKWATER_TOKEN (both required), then the Docker
// credential store for the registry host.
func Resolve(opts Options) (Credentials, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	keychain := opts.Keychain
	if keychain == nil {
		keychain = authn.DefaultKeychain
	}

	switch {
	case opts.Username != "" && !opts.PasswordStdin:
		return Credentials{}, errors.New("--username requires --password-stdin")
	case opts.Username == "" && opts.PasswordStdin:
		return Credentials{}, errors.New("--password-stdin requires --username")
	case opts.Username != "":
		if opts.Stdin == nil {
			return Credentials{}, errors.New("--password-stdin: no stdin available")
		}
		line, err := bufio.NewReader(opts.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return Credentials{}, fmt.Errorf("reading password from stdin: %w", err)
		}
		pw := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if pw == "" {
			return Credentials{}, errors.New("the password read from stdin is empty")
		}
		return Credentials{Username: opts.Username, Password: pw}, nil
	}

	if u, t := getenv("BREAKWATER_USERNAME"), getenv("BREAKWATER_TOKEN"); u != "" && t != "" {
		return Credentials{Username: u, Password: t}, nil
	}

	noCreds := fmt.Errorf(`no credentials: run "docker login %s" with a pull token, or set BREAKWATER_USERNAME and BREAKWATER_TOKEN`, opts.RegistryHost)
	reg, err := name.NewRegistry(opts.RegistryHost)
	if err != nil {
		return Credentials{}, fmt.Errorf("invalid registry host %q: %w", opts.RegistryHost, err)
	}
	auth, err := keychain.Resolve(reg)
	if err != nil {
		return Credentials{}, fmt.Errorf("reading the Docker credential store: %w", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		return Credentials{}, fmt.Errorf("reading the Docker credential store: %w", err)
	}
	if cfg.Username == "" || cfg.Password == "" {
		return Credentials{}, noCreds
	}
	return Credentials{Username: cfg.Username, Password: cfg.Password}, nil
}
