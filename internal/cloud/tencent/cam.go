package tencent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	sdkerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	"github.com/hx-thanadej/keel/internal/ciidentity"
)

// CAMAPI is the slice of CAM used for keyless CI. It deliberately has no
// access-key methods (ADR-0007).
type CAMAPI interface {
	DescribeOIDCConfigWithContext(context.Context, *cam.DescribeOIDCConfigRequest) (*cam.DescribeOIDCConfigResponse, error)
	CreateOIDCConfigWithContext(context.Context, *cam.CreateOIDCConfigRequest) (*cam.CreateOIDCConfigResponse, error)
	UpdateOIDCConfigWithContext(context.Context, *cam.UpdateOIDCConfigRequest) (*cam.UpdateOIDCConfigResponse, error)
	GetRoleWithContext(context.Context, *cam.GetRoleRequest) (*cam.GetRoleResponse, error)
	CreateRoleWithContext(context.Context, *cam.CreateRoleRequest) (*cam.CreateRoleResponse, error)
	UpdateAssumeRolePolicyWithContext(context.Context, *cam.UpdateAssumeRolePolicyRequest) (*cam.UpdateAssumeRolePolicyResponse, error)
}

// NewCAM builds a CAM client for one member account's credentials.
func NewCAM(creds common.Provider) (CAMAPI, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return cam.NewClient(cred, "", profile.NewClientProfile())
}

// CIIdentity implements ciidentity.IAM in one member account.
type CIIdentity struct {
	API CAMAPI
}

var _ ciidentity.IAM = CIIdentity{}

func notFound(err error) bool {
	var e *sdkerr.TencentCloudSDKError
	return errors.As(err, &e) && (strings.HasPrefix(e.Code, "ResourceNotFound") || e.Code == "InvalidParameter.RoleNotExist")
}

// OIDCProvider implements ciidentity.IAM.
func (c CIIdentity) OIDCProvider(ctx context.Context, name string) (ciidentity.Provider, bool, error) {
	req := cam.NewDescribeOIDCConfigRequest()
	req.Name = &name
	res, err := c.API.DescribeOIDCConfigWithContext(ctx, req)
	if notFound(err) {
		return ciidentity.Provider{}, false, nil
	}
	if err != nil {
		return ciidentity.Provider{}, false, fmt.Errorf("DescribeOIDCConfig: %w", err)
	}
	r := res.Response
	if r == nil {
		return ciidentity.Provider{}, false, nil
	}
	p := ciidentity.Provider{AutoRotate: r.AutoRotateKey != nil && *r.AutoRotateKey == 1}
	if r.IdentityUrl != nil {
		p.URL = *r.IdentityUrl
	}
	for _, id := range r.ClientId {
		if id != nil {
			p.ClientIDs = append(p.ClientIDs, *id)
		}
	}
	if r.IdentityKey != nil {
		if raw, err := base64.StdEncoding.DecodeString(*r.IdentityKey); err == nil {
			p.Keys = string(raw)
		}
	}
	return p, true, nil
}

func oidcFields(p ciidentity.Provider) (url, key *string, ids []*string, rotate *uint64) {
	for _, id := range p.ClientIDs {
		ids = append(ids, common.StringPtr(id))
	}
	r := uint64(0)
	if p.AutoRotate {
		r = 1
	}
	return common.StringPtr(p.URL), common.StringPtr(ciidentity.Base64(p.Keys)), ids, &r
}

// CreateOIDCProvider implements ciidentity.IAM.
func (c CIIdentity) CreateOIDCProvider(ctx context.Context, name string, p ciidentity.Provider) error {
	req := cam.NewCreateOIDCConfigRequest()
	req.Name, req.Description = &name, common.StringPtr("Keel: GitHub Actions (keyless CI)")
	req.IdentityUrl, req.IdentityKey, req.ClientId, req.AutoRotateKey = oidcFields(p)
	if _, err := c.API.CreateOIDCConfigWithContext(ctx, req); err != nil {
		return fmt.Errorf("CreateOIDCConfig: %w", err)
	}
	return nil
}

// UpdateOIDCProvider implements ciidentity.IAM.
func (c CIIdentity) UpdateOIDCProvider(ctx context.Context, name string, p ciidentity.Provider) error {
	req := cam.NewUpdateOIDCConfigRequest()
	req.Name, req.Description = &name, common.StringPtr("Keel: GitHub Actions (keyless CI)")
	req.IdentityUrl, req.IdentityKey, req.ClientId, req.AutoRotateKey = oidcFields(p)
	if _, err := c.API.UpdateOIDCConfigWithContext(ctx, req); err != nil {
		return fmt.Errorf("UpdateOIDCConfig: %w", err)
	}
	return nil
}

// RoleTrust implements ciidentity.IAM.
func (c CIIdentity) RoleTrust(ctx context.Context, name string) (string, bool, error) {
	req := cam.NewGetRoleRequest()
	req.RoleName = &name
	res, err := c.API.GetRoleWithContext(ctx, req)
	if notFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("GetRole: %w", err)
	}
	if res.Response == nil || res.Response.RoleInfo == nil || res.Response.RoleInfo.PolicyDocument == nil {
		return "", false, nil
	}
	return *res.Response.RoleInfo.PolicyDocument, true, nil
}

// CreateRole implements ciidentity.IAM. Console login stays off and sessions
// last at most an hour.
func (c CIIdentity) CreateRole(ctx context.Context, name, trust, description string) error {
	req := cam.NewCreateRoleRequest()
	req.RoleName, req.PolicyDocument, req.Description = &name, &trust, &description
	req.ConsoleLogin, req.SessionDuration = common.Uint64Ptr(0), common.Uint64Ptr(3600)
	if _, err := c.API.CreateRoleWithContext(ctx, req); err != nil {
		return fmt.Errorf("CreateRole: %w", err)
	}
	return nil
}

// UpdateRoleTrust implements ciidentity.IAM.
func (c CIIdentity) UpdateRoleTrust(ctx context.Context, name, trust string) error {
	req := cam.NewUpdateAssumeRolePolicyRequest()
	req.RoleName, req.PolicyDocument = &name, &trust
	if _, err := c.API.UpdateAssumeRolePolicyWithContext(ctx, req); err != nil {
		return fmt.Errorf("UpdateAssumeRolePolicy: %w", err)
	}
	return nil
}
