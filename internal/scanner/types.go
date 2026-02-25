package scanner

// Reference represents a GCS bucket/prefix reference found in code.
type Reference struct {
	Bucket  string `json:"bucket"`
	Prefix  string `json:"prefix,omitempty"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Context string `json:"context,omitempty"`
}
