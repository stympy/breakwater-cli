package credentials

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

type fakeKeychain struct{ auth authn.Authenticator }

func (f fakeKeychain) Resolve(authn.Resource) (authn.Authenticator, error) { return f.auth, nil }

func kcWith(u, p string) authn.Keychain {
	return fakeKeychain{authn.FromConfig(authn.AuthConfig{Username: u, Password: p})}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const host = "registry.example.test"

func TestFlagsWinOverEnvAndKeychain(t *testing.T) {
	c, err := Resolve(Options{
		Username: "flaguser", PasswordStdin: true, Stdin: strings.NewReader("flagpass\n"),
		Getenv:       env(map[string]string{"BREAKWATER_USERNAME": "eu", "BREAKWATER_TOKEN": "et"}),
		Keychain:     kcWith("ku", "kp"),
		RegistryHost: host,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c != (Credentials{"flaguser", "flagpass"}) {
		t.Fatalf("got %+v", c)
	}
}

func TestPasswordStdinTrimsNewlines(t *testing.T) {
	for _, in := range []string{"pw\n", "pw\r\n", "pw"} {
		c, err := Resolve(Options{Username: "u", PasswordStdin: true, Stdin: strings.NewReader(in), Getenv: env(nil), RegistryHost: host})
		if err != nil || c != (Credentials{"u", "pw"}) {
			t.Fatalf("input %q: got %+v, %v", in, c, err)
		}
	}
}

func TestPasswordStdinReadsOnlyOneLine(t *testing.T) {
	c, err := Resolve(Options{Username: "u", PasswordStdin: true, Stdin: strings.NewReader("first\nsecond\n"), Getenv: env(nil), RegistryHost: host})
	if err != nil || c.Password != "first" {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestEnvNeedsBothVars(t *testing.T) {
	c, err := Resolve(Options{
		Getenv:       env(map[string]string{"BREAKWATER_USERNAME": "eu", "BREAKWATER_TOKEN": "et"}),
		Keychain:     kcWith("ku", "kp"),
		RegistryHost: host,
	})
	if err != nil || c != (Credentials{"eu", "et"}) {
		t.Fatalf("got %+v, %v", c, err)
	}
	// Only one set: falls through to the keychain.
	c, err = Resolve(Options{
		Getenv:       env(map[string]string{"BREAKWATER_USERNAME": "eu"}),
		Keychain:     kcWith("ku", "kp"),
		RegistryHost: host,
	})
	if err != nil || c != (Credentials{"ku", "kp"}) {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestKeychainUsedLast(t *testing.T) {
	c, err := Resolve(Options{
		Getenv:       env(nil),
		Keychain:     kcWith("ctok_x", "s"),
		RegistryHost: host,
	})
	if err != nil || c != (Credentials{"ctok_x", "s"}) {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestAnonymousKeychainIsNoCredentials(t *testing.T) {
	_, err := Resolve(Options{Getenv: env(nil), Keychain: fakeKeychain{authn.Anonymous}, RegistryHost: host})
	want := `no credentials: run "docker login ` + host + `" with a pull token, or set BREAKWATER_USERNAME and BREAKWATER_TOKEN`
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestUsernameWithoutStdinIsError(t *testing.T) {
	_, err := Resolve(Options{Username: "u", Getenv: env(nil), Keychain: kcWith("a", "b"), RegistryHost: host})
	if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("got %v", err)
	}
}

func TestStdinWithoutUsernameIsError(t *testing.T) {
	_, err := Resolve(Options{PasswordStdin: true, Stdin: strings.NewReader("x\n"), Getenv: env(nil), Keychain: kcWith("a", "b"), RegistryHost: host})
	if err == nil || !strings.Contains(err.Error(), "--username") {
		t.Fatalf("got %v", err)
	}
}

func TestEmptyStdinPasswordIsError(t *testing.T) {
	for _, in := range []string{"", "\n", "\r\n"} {
		_, err := Resolve(Options{Username: "u", PasswordStdin: true, Stdin: strings.NewReader(in), Getenv: env(nil), RegistryHost: host})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("input %q: got %v", in, err)
		}
	}
}
