package tencent

import (
	"context"
	"fmt"
	"strconv"

	cam "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cam/v20190116"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/leaks"
)

// KeyAPI is the slice of CAM used to find and disable access keys.
type KeyAPI interface {
	ListUsersWithContext(context.Context, *cam.ListUsersRequest) (*cam.ListUsersResponse, error)
	ListAccessKeysWithContext(context.Context, *cam.ListAccessKeysRequest) (*cam.ListAccessKeysResponse, error)
	UpdateAccessKeyWithContext(context.Context, *cam.UpdateAccessKeyRequest) (*cam.UpdateAccessKeyResponse, error)
}

// AccessKeys implements leaks.Keys across member accounts.
type AccessKeys struct {
	API func(account string) (KeyAPI, error)
}

var _ leaks.Keys = AccessKeys{}

// Provider implements leaks.Keys.
func (AccessKeys) Provider() string { return "tencent" }

// Find implements leaks.Keys: every sub-user's keys in every account.
func (a AccessKeys) Find(ctx context.Context, keyID string, accounts []string) (leaks.Key, bool, error) {
	for _, acct := range accounts {
		api, err := a.API(acct)
		if err != nil {
			return leaks.Key{}, false, err
		}
		users, err := api.ListUsersWithContext(ctx, cam.NewListUsersRequest())
		if err != nil {
			return leaks.Key{}, false, fmt.Errorf("ListUsers %s: %w", acct, err)
		}
		if users.Response == nil {
			continue
		}
		for _, u := range users.Response.Data {
			if u == nil || u.Uin == nil {
				continue
			}
			req := cam.NewListAccessKeysRequest()
			req.TargetUin = u.Uin
			keys, err := api.ListAccessKeysWithContext(ctx, req)
			if err != nil {
				return leaks.Key{}, false, fmt.Errorf("ListAccessKeys %s: %w", acct, err)
			}
			if keys.Response == nil {
				continue
			}
			for _, k := range keys.Response.AccessKeys {
				if k != nil && k.AccessKeyId != nil && *k.AccessKeyId == keyID {
					return leaks.Key{Provider: "tencent", KeyID: keyID, Account: acct, OwnerUin: strconv.FormatUint(*u.Uin, 10), Owner: deref(u.Name)}, true, nil
				}
			}
		}
	}
	return leaks.Key{}, false, nil
}

// Disable implements leaks.Keys.
func (a AccessKeys) Disable(ctx context.Context, k leaks.Key) error {
	api, err := a.API(k.Account)
	if err != nil {
		return err
	}
	uin, err := strconv.ParseUint(k.OwnerUin, 10, 64)
	if err != nil {
		return err
	}
	req := cam.NewUpdateAccessKeyRequest()
	req.AccessKeyId, req.Status, req.TargetUin = &k.KeyID, common.StringPtr("Inactive"), &uin
	if _, err := api.UpdateAccessKeyWithContext(ctx, req); err != nil {
		return fmt.Errorf("UpdateAccessKey: %w", err)
	}
	return nil
}

// NewKeyAPI builds the CAM client for one member account.
func NewKeyAPI(creds common.Provider) (KeyAPI, error) {
	api, err := NewCAM(creds)
	if err != nil {
		return nil, err
	}
	c, ok := api.(*cam.Client)
	if !ok {
		return nil, fmt.Errorf("unexpected CAM client")
	}
	return c, nil
}
