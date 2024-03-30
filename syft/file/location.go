package file

//该代码定义了 Location 结构体，用于表示文件的位置信息。
import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

// Location represents a path relative to a particular filesystem resolved to a specific file.Reference. This struct is used as a key
// in content fetching to uniquely identify a file relative to a request (the AccessPath).
type Location struct {
	LocationData     `cyclonedx:""`
	LocationMetadata `cyclonedx:""`
}

// LocationData 包含文件定位的核心信息：
// Coordinates: 文件的真实路径 (RealPath) 和文件系统标识 (FileSystemID)。
// RealPath: 文件的实际路径 (绝对或相对)。
// FileSystemID: 文件所在文件系统的标识 (例如，镜像层哈希)。
// AccessPath: 访问该文件的路径 (可能与真实路径不同，例如存在符号链接)。
// ref: 文件在 file.FileCatalog 中的引用 (仅用于来自镜像的 Location)。
type LocationData struct {
	Coordinates `cyclonedx:""` // Empty string here means there is no intermediate property name, e.g. syft:locations:0:path without "coordinates"
	// note: it is IMPORTANT to ignore anything but the coordinates for a Location when considering the ID (hash value)
	// since the coordinates are the minimally correct ID for a location (symlinks should not come into play)
	AccessPath string         `hash:"ignore" json:"accessPath"` // The path to the file which may or may not have hardlinks / symlinks
	ref        file.Reference `hash:"ignore"`                   // The file reference relative to the stereoscope.FileCatalog that has more information about this location.
}

func (l LocationData) Reference() file.Reference {
	return l.ref
}

// LocationMetadata 包含可选的附加信息：
// Annotations: 字典类型的注释，可以存储额外的键值对信息。
type LocationMetadata struct {
	Annotations map[string]string `json:"annotations,omitempty"` // Arbitrary key-value pairs that can be used to annotate a location
}

// 合并两个LocationMetadata
func (m *LocationMetadata) merge(other LocationMetadata) error {
	var errs error
	for k, v := range other.Annotations {
		if otherV, ok := m.Annotations[k]; ok {
			if v != otherV {
				err := fmt.Errorf("unable to merge location metadata: conflicting values for key=%q: %q != %q", k, v, otherV)
				errs = multierror.Append(errs, err)
				continue
			}
		}
		m.Annotations[k] = v
	}
	return errs
}

// 修改LocationMetadata.Annotations信息
func (l Location) WithAnnotation(key, value string) Location {
	if l.LocationMetadata.Annotations == nil {
		l.LocationMetadata.Annotations = map[string]string{}
	}
	l.LocationMetadata.Annotations[key] = value
	return l
}

// 修改LocationMetadata.Annotations信息
func (l Location) WithoutAnnotations() Location {
	l.LocationMetadata.Annotations = map[string]string{}

	return l
}

// NewLocation creates a new Location representing a path without denoting a filesystem or FileCatalog reference.
// NewLocation 创建一个新的 Location 实例，用于表示真实路径。
func NewLocation(realPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
			AccessPath: realPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewVirtualLocation creates a new location for a path accessed by a virtual path (a path with a symlink or hardlink somewhere in the path)
// NewVirtualLocation 创建一个新的 Location 实例，用于表示通过虚拟路径访问的文件 (例如，存在符号链接)。
func NewVirtualLocation(realPath, accessPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: realPath,
			},
			AccessPath: accessPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// 其他 New*LocationFrom* 函数根据不同的来源 (图像、目录) 创建 Location 实例。
// NewLocationFromCoordinates creates a new location for the given Coordinates.
func NewLocationFromCoordinates(coordinates Coordinates) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
			AccessPath:  coordinates.RealPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewVirtualLocationFromCoordinates creates a new location for the given Coordinates via a virtual path.
func NewVirtualLocationFromCoordinates(coordinates Coordinates, accessPath string) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: coordinates,
			AccessPath:  accessPath,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		}}
}

// NewLocationFromImage creates a new Location representing the given path (extracted from the Reference) relative to the given image.
func NewLocationFromImage(accessPath string, ref file.Reference, img *image.Image) Location {
	layer := img.FileCatalog.Layer(ref)
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     string(ref.RealPath),
				FileSystemID: layer.Metadata.Digest,
			},
			AccessPath: accessPath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// NewLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory.
func NewLocationFromDirectory(responsePath string, ref file.Reference) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: responsePath,
			},
			AccessPath: responsePath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

// 用于创建一个新的 Location 实例，该实例表示给定目录中的一個文件，并具有单独的虚拟访问路径。
// NewVirtualLocationFromDirectory creates a new Location representing the given path (extracted from the Reference) relative to the given directory with a separate virtual access path.
func NewVirtualLocationFromDirectory(responsePath, responseAccessPath string, ref file.Reference) Location {
	return Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath: responsePath,
			},
			AccessPath: responseAccessPath,
			ref:        ref,
		},
		LocationMetadata: LocationMetadata{
			Annotations: map[string]string{},
		},
	}
}

func (l Location) Path() string {
	if l.AccessPath != "" {
		return l.AccessPath
	}
	return l.RealPath
}

func (l Location) String() string {
	str := ""
	if l.ref.ID() != 0 {
		str += fmt.Sprintf("id=%d ", l.ref.ID())
	}

	str += fmt.Sprintf("RealPath=%q", l.RealPath)

	if l.AccessPath != "" && l.AccessPath != l.RealPath {
		str += fmt.Sprintf(" AccessPath=%q", l.AccessPath)
	}

	if l.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", l.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}

func (l Location) Equals(other Location) bool {
	return l.RealPath == other.RealPath &&
		l.AccessPath == other.AccessPath &&
		l.FileSystemID == other.FileSystemID
}
