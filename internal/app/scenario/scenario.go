package scenario

import "time"

type HealthT struct {
	Cpu     float32 `json:"cpu_load"`
	Ram     float32 `json:"ram_load"`
	Network float32 `json:"network_load"`
}

type DeviceFingerprintT struct {
	CPU_Serials []string `json:"cpu_serials"`
	RAM_Serials []string `json:"ram_serials"`
	HDD_Serials []string `json:"hdd_serials"`
}

type UserT struct {
	Name          string  `json:"name"`           // Scenario
	PasswAuth     bool    `json:"passw_auth"`     // Scenario
	HWTokenAuth   bool    `json:"hwtoken_auth"`   // Scenario
	FaceIDAuth    bool    `json:"faceid_auth"`    // Scenario
	InputBehavior float32 `json:"input_behavior"` // Scenario
	AccessRate    float32 `json:"access_rate"`    // Scenario
}

type DeviceT struct {
	Name               string             `json:"name"`                 // Scenario
	CertAuth           bool               `json:"cert_auth"`            // Scenario
	HWTokenAuth        bool               `json:"hwtoken_auth"`         // Scenario
	ConnectionSecurity string             `json:"connection_security"`  // Scenario
	SoftwarePatchLevel string             `json:"software_patch_level"` // Scenario
	SystemPatchLevel   string             `json:"system_patch_level"`   // Scenario
	Type               string             `json:"type"`                 // Scenario
	Fingerprint        DeviceFingerprintT `json:"fingerprint"`          // Scenario
	SetupDate          time.Time          `json:"setup_date"`           // Scenario
	LocationIP         string             `json:"location_ip"`          // Scenario
	Health             HealthT            `json:"health"`               // Scenario
	VulnerabilityScan  int                `json:"vulnerability_scan"`   // Scenario
	ManagedDevice      int                `json:"managed_device"`       // Scenario
}

type ChannelT struct {
	Name            string `json:"name"`            // Scenario
	Authentication  string `json:"authentication"`  // Scenario
	Confidentiality string `json:"confidentiality"` // Scenario
	Integrity       string `json:"integrity"`       // Scenario
}

type Scenario struct {
	Id         int64     `json:"id"`
	Name       string    `json:"name"`
	Service    string    `json:"service"`
	Protocol   string    `json:"protocol"`
	Action     string    `json:"action"`
	RemoteAddr string    `json:"remote_addr"`
	AccessTime time.Time `json:"access_time"`
	User       UserT     `json:"user"`
	Device     DeviceT   `json:"device"`
	Channel    ChannelT  `json:"channel"`
}
