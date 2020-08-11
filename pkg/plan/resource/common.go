package resource

type PkgType string

const (
	PkgTypeDeb  PkgType = "Deb"
	PkgTypeRPM  PkgType = "RPM"
	PkgTypeRHEL PkgType = "RHEL"
)
