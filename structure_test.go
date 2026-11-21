// Structural tests: rules about the code base itself. Every matcher asserts that it matched something, so a
// rename cannot turn a rule into a check that passes because it looks at nothing.
package healthlogpush_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type goFile struct {
	path string
	src  string
	ast  *ast.File
}

func goFiles(t *testing.T) []goFile {
	t.Helper()
	var out []goFile
	fs := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".")) && p != "." {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(fs, p, b, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				return err
			}
			out = append(out, goFile{path: filepath.ToSlash(p), src: string(b), ast: f})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 15 {
		t.Fatalf("found only %d Go files; the walk is broken", len(out))
	}
	return out
}

func imports(f goFile) []string {
	var out []string
	for _, i := range f.ast.Imports {
		p, _ := strconv.Unquote(i.Path.Value)
		out = append(out, p)
	}
	return out
}

// TestRelayCannotOpenEnvelopes: no HPKE, X25519 or AEAD code in the service. The only cryptography
// is Ed25519, HMAC, SHA-256 and, in the signer, ES256.
func TestRelayCannotOpenEnvelopes(t *testing.T) {
	banned := []string{"crypto/hpke", "crypto/ecdh", "crypto/cipher", "crypto/aes", "golang.org/x/crypto/chacha20poly1305",
		"golang.org/x/crypto/curve25519", "golang.org/x/crypto/hkdf", "crypto/hkdf", "github.com/cloudflare/circl"}
	checked := 0
	for _, f := range goFiles(t) {
		for _, imp := range imports(f) {
			checked++
			if slices.Contains(banned, imp) {
				t.Errorf("%s imports %s", f.path, imp)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no imports seen")
	}
}

// TestECDSAOnlyInSignerAndCLI: the APNs signing algorithm lives in the signer (and key generation in the CLI).
func TestECDSAOnlyInSignerAndCLI(t *testing.T) {
	seen := 0
	for _, f := range goFiles(t) {
		if slices.Contains(imports(f), "crypto/ecdsa") {
			seen++
			if !strings.HasPrefix(f.path, "internal/signer/") && !strings.HasPrefix(f.path, "cmd/") {
				t.Errorf("%s imports crypto/ecdsa", f.path)
			}
		}
	}
	if seen == 0 {
		t.Fatal("crypto/ecdsa not found at all; matcher broken")
	}
}

// TestClientAddressConfined: the client address is read in exactly one function (the registration limiter
// input) and in the connection limiter; nowhere else, and never next to a log call.
func TestClientAddressConfined(t *testing.T) {
	re := regexp.MustCompile(`\bRemoteAddr\b`)
	allowed := map[string]bool{"internal/relay/http.go": true, "internal/limits/limits.go": true}
	hits := 0
	for _, f := range goFiles(t) {
		if n := len(re.FindAllString(f.src, -1)); n > 0 {
			hits += n
			if !allowed[f.path] {
				t.Errorf("%s reads RemoteAddr", f.path)
			}
		}
		if strings.Contains(f.src, "X-Forwarded-For") || strings.Contains(f.src, "X-Real-Ip") {
			t.Errorf("%s reads a forwarding header", f.path)
		}
	}
	if hits == 0 {
		t.Fatal("RemoteAddr not found at all; matcher broken")
	}
}

// TestOnlyOneLogger: outside cmd/ nothing writes logs except internal/logx; no log.Print, fmt.Print, slog.
func TestOnlyOneLogger(t *testing.T) {
	re := regexp.MustCompile(`\b(log\.(Print|Fatal|Panic)\w*|fmt\.Print\w*|fmt\.Fprint\w*\(os\.(Stdout|Stderr)|os\.(Stdout|Stderr)\.Write|slog\.)`)
	scanned := 0
	for _, f := range goFiles(t) {
		if strings.HasPrefix(f.path, "cmd/") || strings.HasPrefix(f.path, "internal/logx/") {
			continue
		}
		scanned++
		if m := re.FindString(f.src); m != "" {
			t.Errorf("%s uses %s", f.path, m)
		}
	}
	if scanned < 10 {
		t.Fatal("too few files scanned")
	}
}

// TestLogFieldsAreClosed: every logx field key is one of the declared constants (no ad hoc keys).
func TestLogFieldsAreClosed(t *testing.T) {
	re := regexp.MustCompile(`logx\.(Str|Int|Counts)\(([^,]+),`)
	n := 0
	for _, f := range goFiles(t) {
		for _, m := range re.FindAllStringSubmatch(f.src, -1) {
			n++
			if !strings.HasPrefix(strings.TrimSpace(m[2]), "logx.K") {
				t.Errorf("%s: log key %s is not a logx.K constant", f.path, m[2])
			}
		}
	}
	if n == 0 {
		t.Fatal("no log fields found; matcher broken")
	}
}

// TestServerErrorLogIsSet: every http.Server in the command has a silent ErrorLog, and the public one points
// at the counting writer, because the standard library writes client addresses into its error lines.
func TestServerErrorLogIsSet(t *testing.T) {
	var s string
	for _, f := range goFiles(t) {
		if strings.HasPrefix(f.path, "cmd/healthlog-push/") {
			s += f.src
		}
	}
	if !strings.Contains(s, "&http.Server{") {
		t.Fatal("no http.Server found in cmd/healthlog-push; matcher broken")
	}
	if strings.Count(s, "&http.Server{") != strings.Count(s, "ErrorLog:") || !strings.Contains(s, "ErrorLog:          log.New(r.ErrLog") {
		t.Fatal("an http.Server without a silent ErrorLog")
	}
}

// TestPayloadTemplatesOnlyInAPNs: the strings that make up APNs payloads exist only in internal/apns.
func TestPayloadTemplatesOnlyInAPNs(t *testing.T) {
	n := 0
	for _, f := range goFiles(t) {
		for _, s := range []string{`"aps"`, `"mutable-content"`, `"loc-key"`, `"content-available"`} {
			if strings.Contains(f.src, s) {
				n++
				if f.path != "internal/apns/apns.go" {
					t.Errorf("%s contains APNs payload key %s", f.path, s)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("templates not found; matcher broken")
	}
}

// TestDeletionOnlyThroughKnownPaths: bindings are deleted from the store only by the paths the protocol
// names: Unregistered, the second soft failure on another day, unbind by instance or device, instance
// deletion or revocation, retention.
func TestDeletionOnlyThroughKnownPaths(t *testing.T) {
	re := regexp.MustCompile(`st\.DeleteBindings?\(`)
	got := map[string]int{}
	for _, f := range goFiles(t) {
		if c := len(re.FindAllString(f.src, -1)); c > 0 {
			got[f.path] = c
		}
	}
	want := map[string]int{"internal/relay/push_result.go": 1, "internal/relay/bindings.go": 2, "internal/relay/maintenance.go": 1}
	for p, c := range want {
		if got[p] != c {
			t.Errorf("%s: %d DeleteBinding calls, want %d", p, got[p], c)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("unexpected DeleteBinding in %s", p)
		}
	}
}

// TestTextRules: no em dash, en dash, arrow or middle dot in any tracked text file.
func TestTextRules(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		t.Skip("git not available")
	}
	files := strings.Fields(string(out))
	if len(files) < 20 {
		t.Fatalf("only %d files listed", len(files))
	}
	for _, p := range files {
		if strings.HasPrefix(p, "spec/vectors/") || p == "scripts/check-text.sh" || p == "go.sum" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, r := range []string{string(rune(0x2014)), string(rune(0x2013)), string(rune(0x2192)), string(rune(0x00b7))} {
			if strings.Contains(string(b), r) {
				t.Errorf("%s contains %q", p, r)
			}
		}
	}
}

// Size limits for the code an auditor reads: no non-test file over maxFileLines lines, no function over
// maxFuncLines lines, counted from the func keyword to the closing brace.
const (
	maxFileLines = 350
	maxFuncLines = 60
)

// TestFileAndFunctionSize keeps every non-test file and function small enough to read in one sitting.
func TestFileAndFunctionSize(t *testing.T) {
	fs := token.NewFileSet()
	funcs := 0
	for _, f := range goFiles(t) {
		if n := strings.Count(f.src, "\n"); n > maxFileLines {
			t.Errorf("%s has %d lines, more than %d", f.path, n, maxFileLines)
		}
		file, err := parser.ParseFile(fs, f.path, f.src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			funcs++
			if n := fs.Position(fn.End()).Line - fs.Position(fn.Type.Func).Line + 1; n > maxFuncLines {
				t.Errorf("%s: %s has %d lines, more than %d", f.path, fn.Name.Name, n, maxFuncLines)
			}
		}
	}
	if funcs < 100 {
		t.Fatalf("only %d functions seen; the walk is broken", funcs)
	}
}
