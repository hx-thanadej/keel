package tencent_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"
	stsapi "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts/v20180813"
	tcr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tcr/v20190924"

	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fixed struct{ cred common.CredentialIface }

func (f fixed) GetCredential() (common.CredentialIface, error) { return f.cred, nil }

func stored(id, key string) tencent.StoredKey {
	return func(context.Context) (string, string, bool, error) { return id, key, true, nil }
}

// writePaths are every Tencent write Keel makes, reached through the
// constructor its job uses. Each returns the write's error.
var writePaths = map[string]func(ctx context.Context, creds common.Provider) error{
	"vending: CreateOrganizationMember": func(ctx context.Context, c common.Provider) error {
		_, err := tencent.NewOrgAPI("ap-bangkok", c).CreateOrganizationMemberWithContext(ctx, org.NewCreateOrganizationMemberRequest())
		return err
	},
	"landing zone: CreatePolicy": func(ctx context.Context, c common.Provider) error {
		_, err := tencent.NewOrgAPI("ap-bangkok", c).CreatePolicyWithContext(ctx, org.NewCreatePolicyRequest())
		return err
	},
	"landing zone: Attach": func(ctx context.Context, c common.Provider) error {
		return tencent.Guardrails{API: tencent.NewOrgAPI("ap-bangkok", c)}.Attach(ctx, "200000000001", "1", "SERVICE_CONTROL_POLICY")
	},
	"CIC grant: Assign": func(ctx context.Context, c common.Provider) error {
		return tencent.IdentityCenter{API: tencent.NewOrgAPI("ap-bangkok", c), ZoneID: "z-1"}.Assign(ctx, "rc-1", 200000000001, "u-1")
	},
	"CI identity sync: CreateRole": func(ctx context.Context, c common.Provider) error {
		api, err := tencent.NewCAM(c)
		if err != nil {
			return err
		}
		_, err = api.CreateRoleWithContext(ctx, cam.NewCreateRoleRequest())
		return err
	},
	"permission boundary: PutBoundary": func(ctx context.Context, c common.Provider) error {
		b, err := tencent.NewBoundaries(c)
		if err != nil {
			return err
		}
		return b.PutBoundary(ctx, "keel-deploy", 1)
	},
	"leaked key: Disable": func(ctx context.Context, c common.Provider) error {
		return tencent.AccessKeys{API: func(string) (tencent.KeyAPI, error) { return tencent.NewKeyAPI(c) }}.
			Disable(ctx, leaks.Key{Provider: "tencent", KeyID: "AKIDleaked", Account: "200000000001", OwnerUin: "100"})
	},
	"TCR: TempToken": func(ctx context.Context, c common.Provider) error {
		api, err := tencent.NewTCR("ap-bangkok", c)
		if err != nil {
			return err
		}
		_, _, _, err = tencent.Registry{API: api, RegistryID: "tcr-1"}.TempToken(ctx)
		return err
	},
	"TCR: CreateNamespace": func(ctx context.Context, c common.Provider) error {
		api, err := tencent.NewTCR("ap-bangkok", c)
		if err != nil {
			return err
		}
		_, err = api.CreateNamespaceWithContext(ctx, tcr.NewCreateNamespaceRequest())
		return err
	},
	"budget mirror: Create": func(ctx context.Context, c common.Provider) error {
		_, err := tencent.Budgets{Region: "ap-bangkok", Creds: c}.Create(ctx, budget.NativeSpec{Name: "b", Year: 2026})
		return err
	},
	"waste cleanup: release EIP": func(ctx context.Context, c common.Provider) error {
		w, err := tencent.NewWaste("ap-bangkok", c)
		if err != nil {
			return err
		}
		_, err = w.Delete(ctx, rightsize.WasteItem{Kind: "unbound_eip", ResourceID: "eip-1"})
		return err
	},
	"archive: COS write credentials": func(_ context.Context, c common.Provider) error {
		_, _, _, err := tencent.WriteSTS{Creds: c}.Get()
		return err
	},
}

// TestStoredKeyRefusesEveryWritePath runs each write path twice. With a
// writable identity it must send a request, so the case reaches the write.
// With a stored-key identity, directly or through a role assumed from it,
// it must fail with ErrReadOnly and send nothing (ADR-0022).
func TestStoredKeyRefusesEveryWritePath(t *testing.T) {
	ctx := context.Background()
	sts := httptest.NewServer(&fakeSTS{})
	defer sts.Close()
	st := storetest.New(t)
	assumed, err := tencent.NewKeelRole(ctx, st, tencent.Credentials(stored("AKIDstored", "stored-key")), "200000000001", "KeelMember", "ap-bangkok", sts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assumed.GetCredential(); err != nil {
		t.Fatalf("assume from a stored key: %v", err)
	}
	identities := []struct {
		name     string
		creds    common.Provider
		readOnly bool
	}{
		{"writable", fixed{common.NewCredential("AKIDcvm", "k")}, false},
		{"stored key", tencent.Credentials(stored("AKIDstored", "stored-key")), true},
		{"role assumed from a stored key", assumed, true},
	}
	for name, write := range writePaths {
		for _, id := range identities {
			t.Run(name+"/"+id.name, func(t *testing.T) {
				o := &outbound{}
				defer func(t http.RoundTripper) { http.DefaultTransport = t }(http.DefaultTransport)
				http.DefaultTransport = o
				err := write(ctx, id.creds)
				if !id.readOnly {
					if name != "archive: COS write credentials" && len(o.hosts) == 0 {
						t.Fatalf("writable identity sent nothing (err %v); the case does not reach the write", err)
					}
					if errors.Is(err, tencent.ErrReadOnly) || (err != nil && strings.Contains(err.Error(), tencent.ErrReadOnly.Error())) {
						t.Fatalf("writable identity refused: %v", err)
					}
					return
				}
				if len(o.hosts) != 0 {
					t.Errorf("stored-key write sent requests to %v", o.hosts)
				}
				if err == nil || !strings.Contains(err.Error(), tencent.ErrReadOnly.Error()) {
					t.Errorf("err %v, want %v", err, tencent.ErrReadOnly)
				}
			})
		}
	}
}

// TestStoredKeyStillReads: the gate refuses writes only, so discovery,
// audits and drift checks keep working on a stored key.
func TestStoredKeyStillReads(t *testing.T) {
	o := &outbound{}
	defer func(t http.RoundTripper) { http.DefaultTransport = t }(http.DefaultTransport)
	http.DefaultTransport = o
	creds := tencent.Credentials(stored("AKIDstored", "stored-key"))
	api, err := tencent.NewCAM(creds)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.GetRoleWithContext(context.Background(), cam.NewGetRoleRequest())
	if len(o.hosts) != 1 || strings.Contains(fmtErr(err), tencent.ErrReadOnly.Error()) {
		t.Fatalf("GetRole: hosts %v, err %v; want one request and no refusal", o.hosts, err)
	}
	if _, err := (tencent.OrgSource{Region: "ap-bangkok", Creds: creds}).ListAccounts(context.Background()); strings.Contains(fmtErr(err), tencent.ErrReadOnly.Error()) {
		t.Fatalf("discovery refused: %v", err)
	}
	if len(o.hosts) != 2 {
		t.Fatalf("discovery hosts %v", o.hosts)
	}
}

func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestCredentialsChain: a stored connection is the base identity when one
// exists; without one, the keyless chain (here the dev env keys) applies; a
// stored connection that cannot be read fails closed rather than falling
// back to a writable identity.
func TestCredentialsChain(t *testing.T) {
	t.Setenv("KEEL_ENV", "dev")
	t.Setenv("TENCENTCLOUD_SECRET_ID", "AKIDenv")
	t.Setenv("TENCENTCLOUD_SECRET_KEY", "env-key")
	c, err := tencent.Credentials(stored("AKIDstored", "stored-key")).GetCredential()
	if err != nil || c.GetSecretId() != "AKIDstored" || !tencent.IsReadOnly(c) {
		t.Fatalf("stored: %v %v", c, err)
	}
	none := func(context.Context) (string, string, bool, error) { return "", "", false, nil }
	c, err = tencent.Credentials(none).GetCredential()
	if err != nil || c.GetSecretId() != "AKIDenv" || tencent.IsReadOnly(c) {
		t.Fatalf("no connection: %v %v", c, err)
	}
	c, err = tencent.Credentials(nil).GetCredential()
	if err != nil || c.GetSecretId() != "AKIDenv" {
		t.Fatalf("nil stored: %v %v", c, err)
	}
	broken := func(context.Context) (string, string, bool, error) {
		return "", "", false, errors.New("wrong KEEL_SECRETS_KEY")
	}
	if c, err := tencent.Credentials(broken).GetCredential(); err == nil {
		t.Fatalf("broken stored connection fell back to %s", c.GetSecretId())
	}
}

// TestStoredKeyMintsNoCredentials: a read-only identity, directly or
// through a role assumed from it, can send only the reads Keel makes. It
// cannot mint a credential that would not carry the read-only mark, nor
// send a read Keel never makes (some hand out access, such as a VNC URL).
// Each refusal happens before any request leaves Keel; a writable identity
// sends the same call, so each case reaches the send.
func TestStoredKeyMintsNoCredentials(t *testing.T) {
	ctx := context.Background()
	fake := httptest.NewServer(&fakeSTS{})
	defer fake.Close()
	role, err := tencent.NewKeelRole(ctx, storetest.New(t), tencent.Credentials(stored("AKIDstored", "stored-key")), "200000000001", "KeelMember", "ap-bangkok", fake.URL)
	if err != nil {
		t.Fatal(err)
	}
	assumed, err := role.GetCredential()
	if err != nil || !tencent.IsReadOnly(assumed) {
		t.Fatalf("assumed from a stored key: %v, read-only %v", err, tencent.IsReadOnly(assumed))
	}
	identities := map[string]common.CredentialIface{
		"stored key":                     tencent.StoredCredential("AKIDstored", "stored-key"),
		"role assumed from a stored key": assumed,
	}
	calls := map[string]func(common.CredentialIface) error{
		"sts:GetSessionToken (sts client)": func(c common.CredentialIface) error {
			s, err := tencent.StsClient(c, "ap-bangkok", "")
			if err != nil {
				return err
			}
			_, err = s.GetSessionToken(stsapi.NewGetSessionTokenRequest())
			return err
		},
	}
	for _, a := range []struct{ service, version, action string }{
		{"sts", "2018-08-13", "GetSessionToken"},
		{"sts", "2018-08-13", "GetFederationToken"},
		{"sts", "2018-08-13", "AssumeRoleWithWebIdentity"},
		{"sts", "2018-08-13", "AssumeRoleWithSAML"},
		{"sts", "2018-08-13", "QueryApiKey"},
		{"cam", "2019-01-16", "CreateAccessKey"},
		{"cvm", "2017-03-12", "DescribeInstanceVncUrl"},
		{"tcr", "2019-09-24", "DescribeInstanceToken"},
		{"billing", "2018-07-09", "DescribeBillDownloadUrl"},
	} {
		calls[a.service+":"+a.action] = func(c common.CredentialIface) error {
			client, err := tencent.CommonClient(c, "")
			if err != nil {
				return err
			}
			return client.Send(tchttp.NewCommonRequest(a.service, a.version, a.action), tchttp.NewCommonResponse())
		}
	}
	for name, call := range calls {
		for id, cred := range identities {
			t.Run(name+"/"+id, func(t *testing.T) {
				o := &outbound{}
				defer func(t http.RoundTripper) { http.DefaultTransport = t }(http.DefaultTransport)
				http.DefaultTransport = o
				if err := call(common.NewCredential("AKIDcvm", "k")); len(o.hosts) != 1 || strings.Contains(fmtErr(err), tencent.ErrReadOnly.Error()) {
					t.Fatalf("writable identity: hosts %v, err %v; the case does not reach the send", o.hosts, err)
				}
				o.hosts = nil
				err := call(cred)
				if len(o.hosts) != 0 {
					t.Errorf("sent requests to %v", o.hosts)
				}
				if !strings.Contains(fmtErr(err), tencent.ErrReadOnly.Error()) {
					t.Errorf("err %v, want %v", err, tencent.ErrReadOnly)
				}
			})
		}
	}
}

// TestReadsAreExactlyKeelsReads: the read-only allow-list names each read
// Keel's code makes and nothing else, and no credential-minting action.
// A read Keel adds without listing it fails here, not as a refusal in
// production; a listed action Keel no longer makes is a stale grant.
func TestReadsAreExactlyKeelsReads(t *testing.T) {
	made := map[string]bool{}
	for _, f := range repoGoFiles(t) {
		for alias, svc := range sdkServices(f.ast) {
			re := regexp.MustCompile(`\b` + alias + `\.New([A-Z]\w*)Request\(`)
			for _, m := range re.FindAllStringSubmatch(string(f.src), -1) {
				made[svc+":"+m[1]] = true
			}
		}
	}
	readish := regexp.MustCompile(`:(Describe|List|Get|LookUp|Query)`)
	for a := range made {
		if (readish.MatchString(a) || a == "sts:AssumeRole") && !tencent.Reads[a] {
			t.Errorf("Keel makes %s, which the read-only allow-list does not name", a)
		}
	}
	for a := range tencent.Reads {
		if !made[a] {
			t.Errorf("the read-only allow-list names %s, which Keel never makes", a)
		}
		if tencent.Mints[a] {
			t.Errorf("the read-only allow-list names %s, which mints a credential", a)
		}
	}
	for _, a := range []string{"sts:GetSessionToken", "sts:GetFederationToken", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "cam:CreateAccessKey"} {
		if !tencent.Mints[a] {
			t.Errorf("%s is not named as minting a credential", a)
		}
	}
}

type goFile struct {
	path string
	src  []byte
	ast  *ast.File
}

// repoGoFiles are the module's non-test Go files.
func repoGoFiles(t *testing.T) []goFile {
	t.Helper()
	root := "../../.."
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal("repo root not found")
	}
	var out []goFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "vendor" || (strings.HasPrefix(d.Name(), ".") && p != root)) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, goFile{path: filepath.ToSlash(rel), src: src, ast: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const sdk = "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/"

// sdkImports maps each Tencent SDK import's name in f to its package path.
func sdkImports(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasPrefix(p, sdk) {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = p
	}
	return out
}

// sdkServices maps each SDK service package's name in f to its service,
// e.g. cvm -> cvm for .../tencentcloud/cvm/v20170312.
func sdkServices(f *ast.File) map[string]string {
	out := map[string]string{}
	for name, p := range sdkImports(f) {
		if parts := strings.Split(strings.TrimPrefix(p, sdk), "/"); len(parts) == 2 && strings.HasPrefix(parts[1], "v") {
			out[name] = parts[0]
		}
	}
	return out
}

var clientConstructor = regexp.MustCompile(`\.(NewClient|NewClientWith\w+|NewCommonClient)$`)

// unguardedClients names each Tencent SDK client f builds outside guard:
// a NewClient*/NewCommonClient call from any SDK package, or a Client
// literal. guard lives in internal/cloud/tencent, so a client built in any
// other package is unguarded however it is wrapped.
func unguardedClients(file string, f *ast.File) []string {
	pkgs := sdkImports(f)
	inPackage := path.Dir(file) == "internal/cloud/tencent"
	guarded := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && inPackage {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "guard" && len(call.Args) > 0 {
				guarded[call.Args[0]] = true
			}
		}
		return true
	})
	sdkSel := func(e ast.Expr) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || pkgs[x.Name] == "" {
			return "", false
		}
		return x.Name + "." + sel.Sel.Name, true
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if name, ok := sdkSel(n.Fun); ok && clientConstructor.MatchString(name) && !guarded[n] {
				out = append(out, file+": "+name)
			}
		case *ast.CompositeLit:
			if name, ok := sdkSel(n.Type); ok && strings.HasSuffix(name, ".Client") {
				out = append(out, file+": "+name+"{}")
			}
		}
		return true
	})
	return out
}

// TestEverySDKClientIsGuarded: every Tencent SDK client in the module is
// built inside guard, so a client built from a stored key can only read.
func TestEverySDKClientIsGuarded(t *testing.T) {
	checked := 0
	for _, f := range repoGoFiles(t) {
		if len(sdkImports(f.ast)) == 0 {
			continue
		}
		checked++
		for _, u := range unguardedClients(f.path, f.ast) {
			t.Errorf("%s is not built inside guard(...)", u)
		}
	}
	if checked < 10 {
		t.Fatalf("found SDK imports in %d files; the walk is broken", checked)
	}
}

// TestGuardScanCatchesUnguardedClients: the scan above reports each way of
// building an SDK client outside guard.
func TestGuardScanCatchesUnguardedClients(t *testing.T) {
	const imports = `import (
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cbs/v20170312"
	monitor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/monitor/v20180724"
)
`
	for name, c := range map[string]struct {
		file, body string
		want       int
	}{
		"guarded":                   {"internal/cloud/tencent/x.go", `func f(c common.CredentialIface) { guard(billing.NewClient(c, "", profile.NewClientProfile())); guard(common.NewCommonClient(c, "", nil), nil) }`, 0},
		"unguarded NewClient":       {"internal/cloud/tencent/x.go", `func f(c common.CredentialIface) { v20170312.NewClient(c, "", profile.NewClientProfile()) }`, 1},
		"unguarded NewCommonClient": {"internal/cloud/tencent/x.go", `func f(c common.CredentialIface) { common.NewCommonClient(c, "", nil) }`, 1},
		"unguarded in billing.go":   {"internal/cloud/tencent/billing.go", `func f(c common.CredentialIface) { billing.NewClient(c, "", nil) }`, 1},
		"NewClientWithSecretId":     {"internal/cloud/tencent/x.go", `func f() { common.NewClientWithSecretId("a", "b", "") }`, 1},
		"Client literal":            {"internal/cloud/tencent/x.go", `func f() { _ = &monitor.Client{} }`, 1},
		"another package":           {"internal/utilisation/tencent.go", `func f(c common.CredentialIface) { guard(monitor.NewClient(c, "", nil)) }`, 1},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), c.file, "package p\n"+imports+c.body, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := unguardedClients(c.file, f); len(got) != c.want {
				t.Fatalf("reported %v, want %d", got, c.want)
			}
		})
	}
}
