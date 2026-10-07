// Package aws adapts AWS APIs to Keel's provider interfaces.
package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	"github.com/aws/aws-sdk-go-v2/service/budgets/types"

	"github.com/hx-thanadej/keel/internal/budget"
)

// Budgets mirrors Keel Budgets into AWS Budgets (#39) in the management
// account: monthly COST budgets with planned per-month limits, filtered to
// the linked accounts in scope, amortised for effective cost. Thresholds
// become notifications only when Email is set (AWS needs a subscriber).
type Budgets struct {
	AccountID string // management account
	Email     string // optional notification subscriber
	client    *budgets.Client
}

// New loads the default AWS credential chain (web identity / instance role).
func New(ctx context.Context, accountID, email string) (*Budgets, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1")) // AWS Budgets is global, served from us-east-1
	if err != nil {
		return nil, err
	}
	return &Budgets{AccountID: accountID, Email: email, client: budgets.NewFromConfig(cfg)}, nil
}

// Provider implements budget.Native.
func (*Budgets) Provider() string { return "aws" }

// MirrorsThresholds implements budget.ThresholdMirroring.
func (b *Budgets) MirrorsThresholds() bool { return b.Email != "" }

// BudgetFor maps a spec to an AWS budget named name.
func BudgetFor(name string, s budget.NativeSpec) *types.Budget {
	planned := map[string]types.Spend{}
	for i, v := range s.Monthly {
		start := time.Date(s.Year, time.Month(i+1), 1, 0, 0, 0, 0, time.UTC)
		planned[strconv.FormatInt(start.Unix(), 10)] = types.Spend{Amount: sdk.String(v), Unit: sdk.String(s.Currency)}
	}
	metric := types.MetricAmortizedCost // Keel's effective cost
	if s.Basis == "billed" {
		metric = types.MetricUnblendedCost
	}
	return &types.Budget{
		BudgetName:          sdk.String(name),
		BudgetType:          types.BudgetTypeCost,
		TimeUnit:            types.TimeUnitMonthly,
		PlannedBudgetLimits: planned,
		FilterExpression:    &types.Expression{Dimensions: &types.ExpressionDimensionValues{Key: types.DimensionLinkedAccount, Values: s.Accounts}},
		Metrics:             []types.Metric{metric},
		TimePeriod: &types.TimePeriod{
			Start: sdk.Time(time.Date(s.Year, 1, 1, 0, 0, 0, 0, time.UTC)),
			End:   sdk.Time(time.Date(s.Year+1, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
	}
}

// SpecFromBudget reads an AWS budget back into a spec (thresholds excluded;
// they are compared via notifications).
func SpecFromBudget(b *types.Budget) budget.NativeSpec {
	var s budget.NativeSpec
	if b.TimePeriod != nil && b.TimePeriod.Start != nil {
		s.Year = b.TimePeriod.Start.UTC().Year()
	}
	s.Basis = "billed"
	if slices.Contains(b.Metrics, types.MetricAmortizedCost) {
		s.Basis = "effective"
	}
	for k, v := range b.PlannedBudgetLimits {
		sec, err := strconv.ParseInt(k, 10, 64)
		if err != nil || v.Amount == nil {
			continue
		}
		t := time.Unix(sec, 0).UTC()
		if t.Year() == s.Year {
			s.Monthly[t.Month()-1] = *v.Amount
		}
		if v.Unit != nil {
			s.Currency = *v.Unit
		}
	}
	if b.FilterExpression != nil && b.FilterExpression.Dimensions != nil && b.FilterExpression.Dimensions.Key == types.DimensionLinkedAccount {
		s.Accounts = slices.Clone(b.FilterExpression.Dimensions.Values)
	}
	slices.Sort(s.Accounts)
	if b.BudgetName != nil {
		s.Name = *b.BudgetName
	}
	return s
}

func (b *Budgets) notifications(s budget.NativeSpec) []types.NotificationWithSubscribers {
	if b.Email == "" {
		return nil
	}
	var out []types.NotificationWithSubscribers
	for _, t := range s.Thresholds {
		nt := types.NotificationTypeActual
		if t.Basis == "forecast" {
			nt = types.NotificationTypeForecasted
		}
		out = append(out, types.NotificationWithSubscribers{
			Notification: &types.Notification{NotificationType: nt, ComparisonOperator: types.ComparisonOperatorGreaterThan,
				Threshold: t.Pct, ThresholdType: types.ThresholdTypePercentage},
			Subscribers: []types.Subscriber{{SubscriptionType: types.SubscriptionTypeEmail, Address: sdk.String(b.Email)}},
		})
	}
	return out
}

// Create implements budget.Native. The native id is the AWS budget name.
func (b *Budgets) Create(ctx context.Context, s budget.NativeSpec) (string, error) {
	name := fmt.Sprintf("keel-%s-%d", s.Name, s.Year)
	_, err := b.client.CreateBudget(ctx, &budgets.CreateBudgetInput{AccountId: &b.AccountID, Budget: BudgetFor(name, s), NotificationsWithSubscribers: b.notifications(s)})
	if err != nil {
		return "", fmt.Errorf("CreateBudget: %w", err)
	}
	return name, nil
}

// Update implements budget.Native. Notifications are replaced wholesale.
func (b *Budgets) Update(ctx context.Context, id string, s budget.NativeSpec) error {
	if _, err := b.client.UpdateBudget(ctx, &budgets.UpdateBudgetInput{AccountId: &b.AccountID, NewBudget: BudgetFor(id, s)}); err != nil {
		return fmt.Errorf("UpdateBudget: %w", err)
	}
	if b.Email == "" {
		return nil
	}
	old, err := b.client.DescribeNotificationsForBudget(ctx, &budgets.DescribeNotificationsForBudgetInput{AccountId: &b.AccountID, BudgetName: &id})
	if err != nil {
		return err
	}
	for _, n := range old.Notifications {
		if _, err := b.client.DeleteNotification(ctx, &budgets.DeleteNotificationInput{AccountId: &b.AccountID, BudgetName: &id, Notification: &n}); err != nil {
			return err
		}
	}
	for _, n := range b.notifications(s) {
		if _, err := b.client.CreateNotification(ctx, &budgets.CreateNotificationInput{AccountId: &b.AccountID, BudgetName: &id, Notification: n.Notification, Subscribers: n.Subscribers}); err != nil {
			return err
		}
	}
	return nil
}

// Get implements budget.Native.
func (b *Budgets) Get(ctx context.Context, id string) (budget.NativeSpec, bool, error) {
	out, err := b.client.DescribeBudget(ctx, &budgets.DescribeBudgetInput{AccountId: &b.AccountID, BudgetName: &id})
	var nf *types.NotFoundException
	if errors.As(err, &nf) {
		return budget.NativeSpec{}, false, nil
	}
	if err != nil {
		return budget.NativeSpec{}, false, fmt.Errorf("DescribeBudget: %w", err)
	}
	s := SpecFromBudget(out.Budget)
	if b.Email != "" {
		ns, err := b.client.DescribeNotificationsForBudget(ctx, &budgets.DescribeNotificationsForBudgetInput{AccountId: &b.AccountID, BudgetName: &id})
		if err != nil {
			return s, true, err
		}
		for _, n := range ns.Notifications {
			basis := "actual"
			if n.NotificationType == types.NotificationTypeForecasted {
				basis = "forecast"
			}
			s.Thresholds = append(s.Thresholds, budget.Threshold{Pct: n.Threshold, Basis: basis})
		}
	}
	return s, true, nil
}

// Delete implements budget.Native.
func (b *Budgets) Delete(ctx context.Context, id string) error {
	_, err := b.client.DeleteBudget(ctx, &budgets.DeleteBudgetInput{AccountId: &b.AccountID, BudgetName: &id})
	var nf *types.NotFoundException
	if err != nil && !errors.As(err, &nf) {
		return fmt.Errorf("DeleteBudget: %w", err)
	}
	return nil
}
