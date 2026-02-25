package gcs

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// StorageAPI is the interface for GCS operations, allowing mock testing.
type StorageAPI interface {
	ListBuckets(ctx context.Context, projectID string) ([]*storage.BucketAttrs, error)
	BucketAttrs(ctx context.Context, bucket string) (*storage.BucketAttrs, error)
	BucketIAMPolicy(ctx context.Context, bucket string) (*iam.Policy3, error)
	ListObjects(ctx context.Context, bucket string, query *storage.Query) ([]*storage.ObjectAttrs, error)
	Close() error
}

// Client is the real GCS client implementation.
type Client struct {
	client *storage.Client
}

// NewClient creates a new GCS client using Application Default Credentials.
func NewClient(ctx context.Context) (*Client, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	return &Client{client: client}, nil
}

// ListBuckets lists all buckets in the given project.
func (c *Client) ListBuckets(ctx context.Context, projectID string) ([]*storage.BucketAttrs, error) {
	var buckets []*storage.BucketAttrs
	it := c.client.Buckets(ctx, projectID)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}
		buckets = append(buckets, attrs)
	}
	return buckets, nil
}

// BucketAttrs gets the attributes of a specific bucket.
func (c *Client) BucketAttrs(ctx context.Context, bucket string) (*storage.BucketAttrs, error) {
	attrs, err := c.client.Bucket(bucket).Attrs(ctx)
	if err != nil {
		return nil, err
	}
	return attrs, nil
}

// BucketIAMPolicy gets the IAM policy for a bucket.
func (c *Client) BucketIAMPolicy(ctx context.Context, bucket string) (*iam.Policy3, error) {
	policy, err := c.client.Bucket(bucket).IAM().V3().Policy(ctx)
	if err != nil {
		return nil, err
	}
	return policy, nil
}

// ListObjects lists objects in a bucket with the given query parameters.
func (c *Client) ListObjects(ctx context.Context, bucket string, query *storage.Query) ([]*storage.ObjectAttrs, error) {
	var objects []*storage.ObjectAttrs
	it := c.client.Bucket(bucket).Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done || err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		objects = append(objects, attrs)
	}
	return objects, nil
}

// Close closes the underlying GCS client.
func (c *Client) Close() error {
	return c.client.Close()
}
