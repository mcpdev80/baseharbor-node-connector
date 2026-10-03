package capability

type Name string

const (
	RuntimeDetect    Name = "runtime.detect"
	ResourceList     Name = "runtime.resource.list"
	ResourceInspect  Name = "runtime.resource.inspect"
	ImageList        Name = "runtime.image.list"
	ImagePull        Name = "runtime.image.pull"
	VolumeList       Name = "runtime.volume.list"
	VolumeEnsure     Name = "runtime.volume.ensure"
	VolumeRemove     Name = "runtime.volume.remove"
	NetworkList      Name = "runtime.network.list"
	NetworkEnsure    Name = "runtime.network.ensure"
	NetworkRemove    Name = "runtime.network.remove"
	ContainerStart   Name = "runtime.container.start"
	ContainerStop    Name = "runtime.container.stop"
	ContainerRestart Name = "runtime.container.restart"
	ContainerRemove  Name = "runtime.container.remove"
	ComposeApply     Name = "runtime.compose.apply"
	ComposeDestroy   Name = "runtime.compose.destroy"
	QuadletApply     Name = "runtime.quadlet.apply"
	QuadletRemove    Name = "runtime.quadlet.remove"
	QuadletEnable    Name = "runtime.quadlet.enable"
	QuadletDisable   Name = "runtime.quadlet.disable"
	LogRead          Name = "runtime.logs.read"
	Exec             Name = "runtime.exec"
	Terminal         Name = "runtime.terminal"
	Metrics          Name = "runtime.metrics"
	Health           Name = "connector.health"
	Capabilities     Name = "connector.capabilities"
	BundleStage      Name = "artifact.bundle.stage"
)

type Descriptor struct {
	Name      Name   `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}

func Baseline() []Descriptor {
	return []Descriptor{
		{Name: RuntimeDetect, Available: true},
		{Name: ResourceList, Available: true},
		{Name: ResourceInspect, Available: true},
		{Name: ImageList, Available: true},
		{Name: ImagePull, Available: true},
		{Name: VolumeList, Available: true},
		{Name: VolumeEnsure, Available: true},
		{Name: VolumeRemove, Available: true},
		{Name: NetworkList, Available: true},
		{Name: NetworkEnsure, Available: true},
		{Name: NetworkRemove, Available: true},
		{Name: ContainerStart, Available: true},
		{Name: ContainerStop, Available: true},
		{Name: ContainerRestart, Available: true},
		{Name: ContainerRemove, Available: true},
		{Name: ComposeApply, Available: true},
		{Name: ComposeDestroy, Available: true},
		{Name: QuadletApply, Available: true, Detail: "Podman targets only"},
		{Name: QuadletRemove, Available: true, Detail: "Podman targets only"},
		{Name: QuadletEnable, Available: true, Detail: "Podman targets only"},
		{Name: QuadletDisable, Available: true, Detail: "Podman targets only"},
		{Name: LogRead, Available: true},
		{Name: Exec, Available: true},
		{Name: Terminal, Available: false, Detail: "transport/session binding pending BaseHarbor target-access contract"},
		{Name: Metrics, Available: true},
		{Name: Health, Available: true},
		{Name: Capabilities, Available: true},
		{Name: BundleStage, Available: true},
	}
}
