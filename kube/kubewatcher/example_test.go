// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubewatcher_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubewatcher"
)

func Example() {
	// Create a new client
	client, err := kubewatcher.NewClient(kubewatcher.Config{
		BaseURL: "https://kubernetes.default.svc",
		// Token can be loaded from a ServiceAccount token file:
		// /var/run/secrets/kubernetes.io/serviceaccount/token
		Token: "your-token-here",
		// Watch secrets in a specific namespace
		Namespace: "default",
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// List all secrets in the namespace
	ctx := context.Background()
	secrets, err := client.ListSecrets(ctx, "")
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}
	for _, secret := range secrets.Items {
		fmt.Printf("Secret: %s/%s\n", secret.Namespace, secret.Name)
	}

	// Get a specific secret
	secret, err := client.GetSecret(ctx, "default", "my-secret")
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Got secret: %s/%s\n", secret.Namespace, secret.Name)

	// Watch secrets with a 10-second timeout
	watchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	watcher, err := client.WatchSecret(watchCtx, "", kubewatcher.WatchOptions{
		// Optional: Watch only secrets with a specific label
		LabelSelector: "app=example",
	})
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}

	// Start watching in a goroutine
	go func() {
		err := watcher.Watch(func(eventType string, secret *kubeapi.Secret) error {
			fmt.Printf("Event: %s Secret: %s/%s\n", eventType, secret.Namespace, secret.Name)
			return nil
		})
		if err != nil {
			log.Printf("Watch error: %v", err)
		}
	}()

	// Wait for a while then stop the watcher
	time.Sleep(5 * time.Second)
	watcher.Stop()
}
