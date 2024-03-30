package redhat

//该代码片段定义了用于处理 Red Hat (RPM) 软件包的函数，属于 syft 项目的一部分
import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

// newDBPackage 函数:
// 基于来自数据库 (db) 或 RPM 包文件 (dbOrRpmLocation) 的信息创建一个 pkg.Package 对象。
// 该对象包含软件包的名称 (Name)、版本 (Version)、许可证 (Licenses)、PURL (软件包通用资源定位符)、位置 (Locations)、类型 (Type) 和元数据 (Metadata) 等信息。
// toELVersion 函数用于将 RPM 版本转换为 Enterprise Linux (EL) 风格的格式。
// packageURL 函数用于生成软件包的 PURL 字符串。
func newDBPackage(dbOrRpmLocation file.Location, m pkg.RpmDBEntry, distro *linux.Release, licenses []string) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   toELVersion(m.Epoch, m.Version, m.Release),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(dbOrRpmLocation, licenses...)...),
		PURL:      packageURL(m.Name, m.Arch, m.Epoch, m.SourceRpm, m.Version, m.Release, distro),
		Locations: file.NewLocationSet(dbOrRpmLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.RpmPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

// newArchivePackage 函数:
// 基于来自存档文件 (archiveLocation) 的信息创建 pkg.Package 对象，过程类似于 newDBPackage 函数。
func newArchivePackage(archiveLocation file.Location, m pkg.RpmArchive, licenses []string) pkg.Package {
	p := pkg.Package{
		Name:      m.Name,
		Version:   toELVersion(m.Epoch, m.Version, m.Release),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocation(archiveLocation, licenses...)...),
		PURL:      packageURL(m.Name, m.Arch, m.Epoch, m.SourceRpm, m.Version, m.Release, nil),
		Locations: file.NewLocationSet(archiveLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.RpmPkg,
		Metadata:  m,
	}

	p.SetID()
	return p
}

// newMetadataFromManifestLine 函数:
// 解析 RPM 清单文件中的每一行，并从中提取软件包元数据 (e.g., 名称、版本、架构)。
// 该函数专用于解析 Mariner 容器使用的特殊格式的清单文件。
// newMetadataFromManifestLine parses an entry in an RPM manifest file as used in Mariner distroless containers.
// Each line is the output from:
// - rpm --query --all --query-format "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n"
// - https://github.com/microsoft/CBL-Mariner/blob/3df18fac373aba13a54bd02466e64969574f13af/toolkit/docs/how_it_works/5_misc.md?plain=1#L150
func newMetadataFromManifestLine(entry string) (*pkg.RpmDBEntry, error) {
	parts := strings.Split(entry, "\t")
	if len(parts) < 10 {
		return nil, fmt.Errorf("unexpected number of fields in line: %s", entry)
	}

	versionParts := strings.Split(parts[1], "-")
	if len(versionParts) != 2 {
		return nil, fmt.Errorf("unexpected version field: %s", parts[1])
	}
	version := versionParts[0]
	release := versionParts[1]

	converted, err := strconv.Atoi(parts[8])
	var epoch *int
	if err != nil || parts[5] == "(none)" {
		epoch = nil
	} else {
		epoch = &converted
	}

	converted, err = strconv.Atoi(parts[6])
	var size int
	if err == nil {
		size = converted
	}
	return &pkg.RpmDBEntry{
		Name:      parts[0],
		Version:   version,
		Epoch:     epoch,
		Arch:      parts[7],
		Release:   release,
		SourceRpm: parts[9],
		Vendor:    parts[4],
		Size:      size,
	}, nil
}

// packageURL 函数:
// 根据提供的软件包信息生成 PURL 字符串。
// PURL 用于唯一标识软件包，并包含名称、版本、架构、发行版等信息。
// 该函数考虑了发行版 (distro) 信息，可以生成特定于发行版的 PURL。
// packageURL returns the PURL for the specific RHEL package (see https://github.com/package-url/purl-spec)
func packageURL(name, arch string, epoch *int, srpm string, version, release string, distro *linux.Release) string {
	var namespace string
	if distro != nil {
		namespace = distro.ID
	}

	qualifiers := map[string]string{}

	if arch != "" {
		qualifiers[pkg.PURLQualifierArch] = arch
	}

	if epoch != nil {
		qualifiers[pkg.PURLQualifierEpoch] = strconv.Itoa(*epoch)
	}

	if srpm != "" {
		qualifiers[pkg.PURLQualifierUpstream] = srpm
	}

	return packageurl.NewPackageURL(
		packageurl.TypeRPM,
		namespace,
		name,
		// for purl the epoch is a qualifier, not part of the version
		// see https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst under the RPM section
		fmt.Sprintf("%s-%s", version, release),
		pkg.PURLQualifiers(
			qualifiers,
			distro,
		),
		"",
	).ToString()
}
