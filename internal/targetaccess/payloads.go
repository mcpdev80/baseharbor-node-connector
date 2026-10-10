package targetaccess

type ResourceRequest struct {
	ResourceID string `json:"resource_id"`
}

type RemoveResourceRequest struct {
	ResourceID string `json:"resource_id"`
	Force      bool   `json:"force,omitempty"`
}

type ImagePullRequest struct {
	Reference string `json:"reference"`
}

type VolumeEnsureRequest struct {
	Name string `json:"name"`
}

type VolumeRemoveRequest struct {
	Name  string `json:"name"`
	Force bool   `json:"force,omitempty"`
}

type NetworkEnsureRequest struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

type NetworkRemoveRequest struct {
	ResourceID string `json:"resource_id"`
}

type LogsRequest struct {
	ResourceID string `json:"resource_id"`
	Tail       int    `json:"tail,omitempty"`
	Since      string `json:"since,omitempty"`
}

type ExecRequest struct {
	ResourceID     string            `json:"resource_id"`
	Argv           []string          `json:"argv"`
	Workdir        string            `json:"workdir,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
}

type MetricsRequest struct {
	ResourceID string `json:"resource_id"`
}

type ComposeApplyRequest struct {
	ProjectDirectory string   `json:"project_directory"`
	Files            []string `json:"files"`
	EnvFile          string   `json:"env_file,omitempty"`
	Build            bool     `json:"build,omitempty"`
	ForceRecreate    bool     `json:"force_recreate,omitempty"`
	Services         []string `json:"services,omitempty"`
	RemoveOrphans    bool     `json:"remove_orphans,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

type ComposeDestroyRequest struct {
	ProjectDirectory string   `json:"project_directory"`
	Files            []string `json:"files"`
	EnvFile          string   `json:"env_file,omitempty"`
	RemoveOrphans    bool     `json:"remove_orphans,omitempty"`
	Volumes          bool     `json:"volumes,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

type QuadletApplyRequest struct {
	Autostart        *bool  `json:"autostart,omitempty"`
	Name             string `json:"name"`
	Content          string `json:"content"`
	Enable           bool   `json:"enable,omitempty"`
	ProjectDirectory string `json:"project_directory,omitempty"`
}

type QuadletNameRequest struct {
	Name string `json:"name"`
}

// QuadletCompletionRequest can only select a container in an immutable bundle.
// Completion verification observes the source-bound execution; it never starts it.
type QuadletCompletionRequest struct {
	Name             string `json:"name"`
	Content          string `json:"content"`
	ProjectDirectory string `json:"project_directory"`
}

type QuadletCompletionResult struct {
	Name             string `json:"name"`
	ProjectDirectory string `json:"project_directory"`
	ContentSHA256    string `json:"content_sha256"`
	Completed        bool   `json:"completed"`
}

// QuadletVolumeResetRequest selects exact previously realized volume source.
// It cannot force removal, select a host path, or implicitly stop workloads.
type QuadletVolumeResetRequest struct {
	Name             string `json:"name"`
	Content          string `json:"content"`
	ProjectDirectory string `json:"project_directory"`
}
