package gcs

import "time"

// BucketInfo contains metadata about a GCS bucket.
type BucketInfo struct {
	Name                   string            `json:"name"`
	Exists                 bool              `json:"exists"`
	Project                string            `json:"project,omitempty"`
	Location               string            `json:"location,omitempty"`
	StorageClass           string            `json:"storage_class,omitempty"`
	CreationDate           *time.Time        `json:"creation_date,omitempty"`
	LastUpdated            *time.Time        `json:"last_updated,omitempty"`
	DaysSinceUpdate        int               `json:"days_since_update"`
	AgeInDays              int               `json:"age_in_days"`
	VersioningEnabled      bool              `json:"versioning_enabled"`
	LifecycleRules         int               `json:"lifecycle_rules"`
	LifecycleHasDelete     bool              `json:"lifecycle_has_delete"`
	LifecycleHasArchive    bool              `json:"lifecycle_has_archive"`
	UniformAccessEnabled   bool              `json:"uniform_access_enabled"`
	PublicAccessPrevention string            `json:"public_access_prevention,omitempty"`
	RetentionPolicySet     bool              `json:"retention_policy_set"`
	RetentionPeriodSeconds int64             `json:"retention_period_seconds,omitempty"`
	Labels                 map[string]string `json:"labels,omitempty"`
	IsEmpty                bool              `json:"is_empty"`
	ObjectCount            int               `json:"object_count,omitempty"`
	TotalSize              int64             `json:"total_size,omitempty"`
	SampleObjects          []ObjectSample    `json:"sample_objects,omitempty"`
	PublicAccess           *PublicAccessInfo `json:"public_access,omitempty"`
	Prefixes               []PrefixInfo      `json:"prefixes,omitempty"`
	Error                  string            `json:"error,omitempty"`
}

// ObjectSample contains metadata for a sampled object.
type ObjectSample struct {
	Name         string    `json:"name"`
	Size         int64     `json:"size"`
	Updated      time.Time `json:"updated"`
	StorageClass string    `json:"storage_class,omitempty"`
}

// PublicAccessInfo contains public access check results.
type PublicAccessInfo struct {
	IsPublic      bool     `json:"is_public"`
	PublicMembers []string `json:"public_members,omitempty"`
	PublicRoles   []string `json:"public_roles,omitempty"`
}

// PrefixInfo contains metadata about a GCS prefix.
type PrefixInfo struct {
	Prefix           string     `json:"prefix"`
	Exists           bool       `json:"exists"`
	ObjectCount      int        `json:"object_count"`
	LatestUpdated    *time.Time `json:"latest_updated,omitempty"`
	DaysSinceUpdated int        `json:"days_since_updated,omitempty"`
}
