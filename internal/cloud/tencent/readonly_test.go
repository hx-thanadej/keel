package tencent_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"
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

// TestEverySDKClientIsGuarded: every Tencent SDK client the package builds
// passes through guard, so a client built from a stored key can only read.
// billing.go only reads bills (DescribeBillSummaryByPayMode).
func TestEverySDKClientIsGuarded(t *testing.T) {
	unguardedOK := map[string]bool{"billing.go": true}
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || unguardedOK[path] {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		guarded := map[ast.Node]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "guard" && len(call.Args) == 1 {
					guarded[call.Args[0]] = true
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "NewClient" {
				checked++
				if !guarded[call] {
					t.Errorf("%s: %s.NewClient is not wrapped in guard(...)", path, sel.X)
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("found no SDK clients; the check is broken")
	}
}
