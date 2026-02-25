package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var initFlags struct {
	project string
	force   bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate .gcsspectre.yaml config and IAM policy",
	Long: `Generates a .gcsspectre.yaml configuration file with sensible defaults
and prints the minimum IAM policy needed for gcsspectre to scan your project.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVarP(&initFlags.project, "project", "p", "", "GCP project ID")
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing config file")
}

const configTemplate = `# gcsspectre configuration
# See: https://github.com/ppiankov/gcsspectre

project: "%s"

# Days since last object update before prefix is considered stale
stale_days: 90

# Days threshold for noncurrent version cleanup recommendations
version_days: 30

# Output format: text, json, sarif, spectrehub
format: text

# Check for public bucket access via IAM policy
check_public: true

# Buckets to exclude from analysis
# exclude_buckets:
#   - my-public-website-bucket
#   - another-bucket

# Operation timeout (Go duration string)
# timeout: 5m
`

const iamPolicyTemplate = `
Minimum IAM policy for gcsspectre (read-only):

  gcloud projects add-iam-policy-binding %s \
    --member="user:YOUR_EMAIL" \
    --role="roles/storage.objectViewer"

  gcloud projects add-iam-policy-binding %s \
    --member="user:YOUR_EMAIL" \
    --role="roles/storage.admin" \
    --condition='expression=resource.type == "storage.googleapis.com/Bucket",title=BucketMetadataOnly'

Or use a custom role with these permissions:
  - storage.buckets.list
  - storage.buckets.get
  - storage.buckets.getIamPolicy
  - storage.objects.list
  - storage.objects.get

For service accounts, replace "user:YOUR_EMAIL" with "serviceAccount:SA_EMAIL".
`

func runInit(_ *cobra.Command, _ []string) error {
	configPath := ".gcsspectre.yaml"

	if !initFlags.force {
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", configPath)
		}
	}

	project := initFlags.project
	if project == "" {
		project = "YOUR_PROJECT_ID"
	}

	content := fmt.Sprintf(configTemplate, project)
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("Created %s\n", configPath)
	fmt.Printf(iamPolicyTemplate, project, project)

	return nil
}
