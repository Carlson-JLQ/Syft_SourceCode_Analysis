package pkg

//该代码定义了用于处理 RPM 软件包信息的包
import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// RpmDBGlob is the glob pattern used to find RPM DB files. Where:
// - /var/lib/rpm/... is the typical path for most distributions
// - /usr/share/rpm/... is common for rpm-ostree distributions (coreos-like)
// - Packages is the legacy Berkeley db based format
// - Packages.db is the "ndb" format used in SUSE
// - rpmdb.sqlite is the sqlite format used in fedora + derivates
// RpmDBGlob: 用于查找 RPM 数据库文件的 glob 模式，涵盖多种常见路径和格式 (Packages, Packages.db, rpmdb.sqlite)。
const RpmDBGlob = "**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}"

// RpmManifestGlob: 用于 CBL-Mariner 发行版的特定 glob 模式。
// RpmManifestGlob is used in CBL-Mariner distroless images
const RpmManifestGlob = "**/var/lib/rpmmanifest/container-manifest-2"

var _ FileOwner = (*RpmDBEntry)(nil)

// RpmArchive: 是 RpmDBEntry 的别名，用于强调其来源。
// RpmArchive represents all captured data from a RPM package archive.
type RpmArchive RpmDBEntry

// RpmDBEntry: 表示 RPM 数据库中的单个软件包条目，包含名称、版本、架构、文件列表等信息。
// RpmDBEntry represents all captured data from a RPM DB package entry.
type RpmDBEntry struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Epoch           *int            `json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`
	Arch            string          `json:"architecture"`
	Release         string          `json:"release" cyclonedx:"release"`
	SourceRpm       string          `json:"sourceRpm" cyclonedx:"sourceRpm"`
	Size            int             `json:"size" cyclonedx:"size"`
	Vendor          string          `json:"vendor"`
	ModularityLabel *string         `json:"modularityLabel,omitempty"`
	Files           []RpmFileRecord `json:"files"`
}

// RpmFileRecord: 表示 RPM 包内单个文件的详细信息，包含路径、权限、大小、哈希值等信息。
// RpmFileRecord represents the file metadata for a single file attributed to a RPM package.
type RpmFileRecord struct {
	Path      string      `json:"path"`
	Mode      RpmFileMode `json:"mode"`
	Size      int         `json:"size"`
	Digest    file.Digest `json:"digest"`
	UserName  string      `json:"userName"`
	GroupName string      `json:"groupName"`
	Flags     string      `json:"flags"`
}

// RpmFileMode: 表示文件的原始权限模式 (参考 stat.h)。
// RpmFileMode is the raw file mode for a single file. This can be interpreted as the linux stat.h mode (see https://pubs.opengroup.org/onlinepubs/007908799/xsh/sysstat.h.html)
type RpmFileMode uint16

// (RpmDBEntry).OwnedFiles: 提取 RPM 包拥有的文件列表，并排序输出。
func (m RpmDBEntry) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
