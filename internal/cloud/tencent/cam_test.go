package tencent_test

import (
	"context"
	"encoding/base64"
	"testing"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	sdkerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"

	"github.com/hx-thanadej/keel/internal/ciidentity"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

type fakeCAM struct {
	oidc  *cam.CreateOIDCConfigRequest
	trust *string
	role  *cam.CreateRoleRequest
}

func (f *fakeCAM) DescribeOIDCConfigWithContext(context.Context, *cam.DescribeOIDCConfigRequest) (*cam.DescribeOIDCConfigResponse, error) {
	if f.oidc == nil {
		return nil, sdkerr.NewTencentCloudSDKError("ResourceNotFound.IdentityNotExist", "no", "r")
	}
	res := cam.NewDescribeOIDCConfigResponse()
	res.Response = &cam.DescribeOIDCConfigResponseParams{IdentityUrl: f.oidc.IdentityUrl, IdentityKey: f.oidc.IdentityKey, ClientId: f.oidc.ClientId, AutoRotateKey: f.oidc.AutoRotateKey}
	return res, nil
}
func (f *fakeCAM) CreateOIDCConfigWithContext(_ context.Context, r *cam.CreateOIDCConfigRequest) (*cam.CreateOIDCConfigResponse, error) {
	f.oidc = r
	return cam.NewCreateOIDCConfigResponse(), nil
}
func (f *fakeCAM) UpdateOIDCConfigWithContext(context.Context, *cam.UpdateOIDCConfigRequest) (*cam.UpdateOIDCConfigResponse, error) {
	panic("unexpected update")
}
func (f *fakeCAM) GetRoleWithContext(context.Context, *cam.GetRoleRequest) (*cam.GetRoleResponse, error) {
	if f.trust == nil {
		return nil, sdkerr.NewTencentCloudSDKError("InvalidParameter.RoleNotExist", "no", "r")
	}
	res := cam.NewGetRoleResponse()
	res.Response = &cam.GetRoleResponseParams{RoleInfo: &cam.RoleInfo{PolicyDocument: f.trust}}
	return res, nil
}
func (f *fakeCAM) CreateRoleWithContext(_ context.Context, r *cam.CreateRoleRequest) (*cam.CreateRoleResponse, error) {
	f.role, f.trust = r, r.PolicyDocument
	return cam.NewCreateRoleResponse(), nil
}
func (f *fakeCAM) UpdateAssumeRolePolicyWithContext(context.Context, *cam.UpdateAssumeRolePolicyRequest) (*cam.UpdateAssumeRolePolicyResponse, error) {
	panic("unexpected update")
}

func TestCIIdentityOnCAM(t *testing.T) {
	f := &fakeCAM{}
	iam := tencent.CIIdentity{API: f}
	jwks := `{"keys":[{"kid":"k1"}]}`
	subs := []string{"repository_owner_id:42:repository_id:900:environment:prod"}
	ch, err := ciidentity.Ensure(context.Background(), iam, "100001", ciidentity.Config{}, jwks, subs)
	if err != nil || !ch.ProviderCreated || !ch.RoleCreated {
		t.Fatal(ch, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(*f.oidc.IdentityKey)
	if string(raw) != jwks || *f.oidc.AutoRotateKey != 1 || *f.oidc.IdentityUrl != ciidentity.GitHubIssuer {
		t.Fatalf("oidc %+v", f.oidc)
	}
	if *f.role.ConsoleLogin != 0 || *f.role.SessionDuration != 3600 {
		t.Fatalf("role %+v", f.role)
	}
	// Second pass reads back what was written and changes nothing (fakes panic on updates).
	if ch, err := ciidentity.Ensure(context.Background(), iam, "100001", ciidentity.Config{}, jwks, subs); err != nil || ch != (ciidentity.Change{}) {
		t.Fatal(ch, err)
	}
}
