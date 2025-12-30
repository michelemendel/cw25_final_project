package main

import (
	"time"

	"github.com/cschleiden/go-workflows/workflow"
)

func ReconWorkflow(ctx workflow.Context, domain string) error {
	var activity *Activities // Activity struct is just a placeholder for the activity names

	// Retry policy for transient errors (e.g. network issues)
	retryOptions := workflow.RetryOptions{
		MaxAttempts:        3,
		FirstRetryInterval: 1 * time.Second,
		BackoffCoefficient: 2.0,
		MaxRetryInterval:   10 * time.Second,
	}

	// Activity options - timeouts are handled at the workflow level
	// Activities use CommandContext which respects workflow context cancellation
	activityOptions := workflow.ActivityOptions{
		RetryOptions: retryOptions,
	}

	// Parse Scope
	// Get returns (result, error). Since we use [any], result is ignored.
	if _, err := workflow.ExecuteActivity[any](ctx, activityOptions, activity.ParseScope, domain).Get(ctx); err != nil {
		return err
	}

	// Subdomain Enumeration
	if _, err := workflow.ExecuteActivity[any](ctx, activityOptions, activity.DiscoverSubdomains, domain).Get(ctx); err != nil {
		return err
	}

	// Web Liveness
	if _, err := workflow.ExecuteActivity[any](ctx, activityOptions, activity.IdentifyLiveHosts, domain).Get(ctx); err != nil {
		return err
	}

	// Vulnerability Scanning
	if _, err := workflow.ExecuteActivity[any](ctx, activityOptions, activity.ScanVulnerabilities, domain).Get(ctx); err != nil {
		return err
	}

	// Reporting
	if _, err := workflow.ExecuteActivity[any](ctx, activityOptions, activity.GenerateReport, domain).Get(ctx); err != nil {
		return err
	}

	return nil
}
