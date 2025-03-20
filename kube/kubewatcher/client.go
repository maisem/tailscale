// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package kubewatcher implements a simple Kubernetes client that watches secrets
// without using any generated clients.
package kubewatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"tailscale.com/kube/kubeapi"
	"tailscale.com/syncs"
)

// Client is a simple Kubernetes client that watches secrets.
type Client struct {
	// baseURL is the URL of the Kubernetes API server.
	baseURL string
	// httpClient is the HTTP client used to make requests to the Kubernetes API server.
	httpClient *http.Client
	// token is the bearer token used to authenticate with the Kubernetes API server.
	token string
	// namespace is the namespace to watch secrets in. If empty, all namespaces will be watched.
	namespace string
	// latestSecret stores the most recently received secret in memory.
	// It uses syncs.Map for thread-safe concurrent access.
	latestSecret syncs.Map[string, *kubeapi.Secret] // key is "namespace/name"
}

// Config is configuration for a new Kubernetes client.
type Config struct {
	// BaseURL is the URL of the Kubernetes API server.
	BaseURL string
	// HTTPClient is the HTTP client used to make requests to the Kubernetes API server.
	HTTPClient *http.Client
	// Token is the bearer token used to authenticate with the Kubernetes API server.
	Token string
	// Namespace is the namespace to watch secrets in. If empty, all namespaces will be watched.
	Namespace string
}

// NewClient creates a new Kubernetes client.
func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}

	return &Client{
		baseURL:      strings.TrimSuffix(config.BaseURL, "/"),
		httpClient:   config.HTTPClient,
		token:        config.Token,
		namespace:    config.Namespace,
		latestSecret: syncs.Map[string, *kubeapi.Secret]{},
	}, nil
}

// SecretWatcher watches secrets in a namespace.
type SecretWatcher struct {
	client          *Client
	ctx             context.Context
	cancel          context.CancelFunc
	namespace       string
	fieldSelector   string
	labelSelector   string
	resourceVersion string
}

// WatchOptions configures a watch request.
type WatchOptions struct {
	// FieldSelector is a selector to restrict the list of returned objects by their fields.
	// Defaults to everything.
	FieldSelector string
	// LabelSelector is a selector to restrict the list of returned objects by their labels.
	// Defaults to everything.
	LabelSelector string
	// ResourceVersion is the resource version to start watching from.
	ResourceVersion string
}

// WatchSecret creates a new watcher for secrets in the specified namespace.
func (c *Client) WatchSecret(ctx context.Context, namespace string, options WatchOptions) (*SecretWatcher, error) {
	if namespace == "" {
		namespace = c.namespace
	}

	ctx, cancel := context.WithCancel(ctx)

	return &SecretWatcher{
		client:          c,
		ctx:             ctx,
		cancel:          cancel,
		namespace:       namespace,
		fieldSelector:   options.FieldSelector,
		labelSelector:   options.LabelSelector,
		resourceVersion: options.ResourceVersion,
	}, nil
}

// Watch starts watching secrets and calls the callback function for each event.
// This function blocks until the context is canceled or an error occurs.
func (w *SecretWatcher) Watch(callback func(eventType string, secret *kubeapi.Secret) error) error {
	path := "/api/v1/secrets"
	if w.namespace != "" {
		path = fmt.Sprintf("/api/v1/namespaces/%s/secrets", w.namespace)
	}

	// Build query parameters
	query := url.Values{}
	query.Set("watch", "true")

	if w.fieldSelector != "" {
		query.Set("fieldSelector", w.fieldSelector)
	}
	if w.labelSelector != "" {
		query.Set("labelSelector", w.labelSelector)
	}
	if w.resourceVersion != "" {
		query.Set("resourceVersion", w.resourceVersion)
	}

	// Build request URL
	u := fmt.Sprintf("%s%s?%s", w.client.baseURL, path, query.Encode())

	req, err := http.NewRequestWithContext(w.ctx, "GET", u, nil)
	if err != nil {
		return fmt.Errorf("creating watch request: %v", err)
	}

	if w.client.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.client.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending watch request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("watch request failed: %s: %s", resp.Status, body)
	}

	decoder := json.NewDecoder(resp.Body)

	for {
		var event struct {
			Type   string         `json:"type"`
			Object kubeapi.Secret `json:"object"`
		}

		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF || w.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("decoding watch event: %v", err)
		}

		// Store the latest secret in memory
		secretKey := fmt.Sprintf("%s/%s", event.Object.Namespace, event.Object.Name)
		switch event.Type {
		case "ADDED", "MODIFIED":
			w.client.latestSecret.Store(secretKey, &event.Object)
		case "DELETED":
			w.client.latestSecret.Delete(secretKey)
		}

		if callback != nil {
			if err := callback(event.Type, &event.Object); err != nil {
				return err
			}
		}
	}
}

// Stop stops watching.
func (w *SecretWatcher) Stop() {
	w.cancel()
}

// GetSecret gets a secret by name in the specified namespace.
func (c *Client) GetSecret(ctx context.Context, namespace, name string) (*kubeapi.Secret, error) {
	if namespace == "" {
		namespace = c.namespace
	}
	if namespace == "" {
		return nil, fmt.Errorf("namespace is required")
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, name)
	u := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s: %s", resp.Status, body)
	}

	var secret kubeapi.Secret
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, fmt.Errorf("decoding response: %v", err)
	}

	return &secret, nil
}

// GetCachedSecret retrieves a secret from the in-memory cache.
// Returns nil if the secret is not in the cache.
func (c *Client) GetCachedSecret(namespace, name string) (*kubeapi.Secret, bool) {
	secretKey := fmt.Sprintf("%s/%s", namespace, name)
	// TODO: clone.
	return c.latestSecret.Load(secretKey)
}

// ListSecrets lists secrets in the specified namespace.
func (c *Client) ListSecrets(ctx context.Context, namespace string) (*kubeapi.SecretList, error) {
	if namespace == "" {
		namespace = c.namespace
	}

	path := "/api/v1/secrets"
	if namespace != "" {
		path = fmt.Sprintf("/api/v1/namespaces/%s/secrets", namespace)
	}

	u := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed: %s: %s", resp.Status, body)
	}

	var secretList kubeapi.SecretList
	if err := json.NewDecoder(resp.Body).Decode(&secretList); err != nil {
		return nil, fmt.Errorf("decoding response: %v", err)
	}

	return &secretList, nil
}
