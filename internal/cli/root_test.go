package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testIO(stdin string, env map[string]string) (*IOStreams, *bytes.Buffer, *bytes.Buffer) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	return &IOStreams{
		In: strings.NewReader(stdin), Out: out, Err: errb,
		Getenv: func(k string) string { return env[k] },
	}, out, errb
}

func TestVersionOutput(t *testing.T) {
	ios, out, errb := testIO("", nil)
	if code := execute(ios, []string{"version"}); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	if !strings.HasPrefix(out.String(), "breakwater dev (") || !strings.HasSuffix(out.String(), ")\n") {
		t.Fatalf("got %q", out)
	}
}

func TestUnknownCommandExitsOne(t *testing.T) {
	ios, _, errb := testIO("", nil)
	if code := execute(ios, []string{"bogus"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(errb.String(), "breakwater: ") || strings.Contains(errb.String(), "Usage:") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestFlagErrorPrintsUsage(t *testing.T) {
	ios, _, errb := testIO("", nil)
	if code := execute(ios, []string{"version", "--nope"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "Usage:") || !strings.Contains(errb.String(), "breakwater: ") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestAPIOrigin(t *testing.T) {
	for host, want := range map[string]string{
		"https://app.example.com":  "https://app.example.com",
		"http://127.0.0.1:3000":    "http://127.0.0.1:3000",
		"https://app.example.com/": "https://app.example.com",
	} {
		u, err := (&globals{host: host}).APIOrigin()
		if err != nil || u.String() != want {
			t.Errorf("%q: got %v, %v", host, u, err)
		}
	}
	for _, host := range []string{
		"https://app.example.com/api", "https://user:pw@app.example.com", "https://app.example.com?x=1",
		"https://app.example.com/#f", "ftp://app.example.com", "https://", "", "app.example.com",
	} {
		if u, err := (&globals{host: host}).APIOrigin(); err == nil {
			t.Errorf("%q: accepted as %v", host, u)
		}
	}
}

func TestCredentialsReadsPasswordFromInjectedStdin(t *testing.T) {
	ios, _, _ := testIO("s3cret\r\n", nil)
	root := newRootCommand(ios)
	if err := root.ParseFlags([]string{"--username", "ctok_x", "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	// Reach the globals through the flags the root registered.
	g := &globals{io: ios}
	g.username, _ = root.PersistentFlags().GetString("username")
	g.passwordStdin, _ = root.PersistentFlags().GetBool("password-stdin")
	cmd := &cobra.Command{}
	cmd.SetIn(ios.In)
	c, err := g.Credentials(cmd)
	if err != nil || c.Username != "ctok_x" || c.Password != "s3cret" {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestNewRootCommandDoesNotMutateStreams(t *testing.T) {
	ios := &IOStreams{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	newRootCommand(ios)
	if ios.Getenv != nil {
		t.Fatal("caller's IOStreams was modified")
	}
}
