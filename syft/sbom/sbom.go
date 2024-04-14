package sbom

import (
	"slices"
	"sort"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// SBOM：此结构表示 SBOM 数据的核心。它包含以下字段：
// Artifacts：此字段存储有关软件工件的信息，例如包、文件及其属性。
// Relationships：此字段保存工件之间的关系列表，可能描述依赖关系或交互。
// Source：此字段存储有关 SBOM 数据来源的信息。
// Descriptor：此字段包含一个通用描述符，其中包含名称、版本和可选配置信息。
type SBOM struct {
	Artifacts     Artifacts
	Relationships []artifact.Relationship
	Source        source.Description
	Descriptor    Descriptor
}

// Artifacts：此嵌套结构包含有关 SBOM 中软件工件的详细信息。
// Packages：此字段指向包对象的集合（可能包含名称、版本、许可证等详细信息）。
// FileMetadata：此映射存储由坐标（可能是在软件内的路径）标识的单个文件的元数据（例如大小、权限）。
// FileDigests：此映射存储由坐标标识的文件的加密摘要（哈希）。
// FileContents：此映射存储一些由坐标标识的文件的实际内容（可选）。
// FileLicenses：此映射存储与由坐标标识的文件关联的许可证信息。
// Executables：此映射存储有关由坐标标识的可执行文件的信息。
// LinuxDistribution：此字段包含有关 SBOM 数据关联的 Linux 发行版的信息（如果适用）。
type Artifacts struct {
	Packages          *pkg.Collection
	FileMetadata      map[file.Coordinates]file.Metadata
	FileDigests       map[file.Coordinates][]file.Digest
	FileContents      map[file.Coordinates]string
	FileLicenses      map[file.Coordinates][]file.License
	Executables       map[file.Coordinates]file.Executable
	LinuxDistribution *linux.Release
}

// Descriptor：此结构提供了一种通用方式来描述 SBOM 本身。
// Name：此字段存储 SBOM 的名称。
// Version：此字段存储 SBOM 格式的版本。
// Configuration：此字段可以灵活地保存任何特定于 SBOM 的附加配置数据。
type Descriptor struct {
	Name          string
	Version       string
	Configuration interface{}
}

// RelationshipsSorted()：此函数根据工件 ID 和关系类型对 SBOM 中的关系进行排序。
func (s SBOM) RelationshipsSorted() []artifact.Relationship {
	relationships := s.Relationships
	sort.SliceStable(relationships, func(i, j int) bool {
		if relationships[i].From.ID() == relationships[j].From.ID() {
			if relationships[i].To.ID() == relationships[j].To.ID() {
				return relationships[i].Type < relationships[j].Type
			}
			return relationships[i].To.ID() < relationships[j].To.ID()
		}
		return relationships[i].From.ID() < relationships[j].From.ID()
	})
	return relationships
}

// 此函数收集 SBOM 数据中跨越多个字段（元数据、摘要、内容等）提到的所有唯一文件坐标。
func (s SBOM) AllCoordinates() []file.Coordinates {
	set := file.NewCoordinateSet()
	for coordinates := range s.Artifacts.FileMetadata {
		set.Add(coordinates)
	}
	for coordinates := range s.Artifacts.FileContents {
		set.Add(coordinates)
	}
	for coordinates := range s.Artifacts.FileDigests {
		set.Add(coordinates)
	}
	for _, relationship := range s.Relationships {
		for _, coordinates := range extractCoordinates(relationship) {
			set.Add(coordinates)
		}
	}
	//根据一定的规则排序
	return set.ToSlice()
}

// 此函数将 SBOM 中的关系筛选为涉及特定包的关系，并可以选择按关系类型进行筛选。
// 输入packega和相关的关系类型，筛选出来对应的关系列表
// RelationshipsForPackage returns all relationships for the provided types.
// If no types are provided, all relationships for the package are returned.
func (s SBOM) RelationshipsForPackage(p pkg.Package, rt ...artifact.RelationshipType) []artifact.Relationship {
	if len(rt) == 0 {
		rt = artifact.AllRelationshipTypes()
	}

	var relationships []artifact.Relationship
	for _, relationship := range s.Relationships {
		if relationship.From == nil || relationship.To == nil {
			log.Debugf("relationship has nil edge, skipping: %#v", relationship)
			continue
		}
		if relationship.From.ID() != p.ID() {
			continue
		}
		// check if the relationship is one we're searching for; rt is inclusive
		if !slices.ContainsFunc(rt, func(r artifact.RelationshipType) bool { return relationship.Type == r }) {
			continue
		}
		relationships = append(relationships, relationship)
	}

	return relationships
}

// 此函数根据特定包在 SBOM 中的关系（可选地按关系类型过滤）检索所有关联的文件坐标
// CoordinatesForPackage returns all coordinates for the provided package for provided relationship types
// If no types are provided, all relationship types are considered.
// rt 是类型为 ...artifact.RelationshipType 的参数。这意味着该函数可以接收零个或多个类型为 artifact.RelationshipType 的参数。
func (s SBOM) CoordinatesForPackage(p pkg.Package, rt ...artifact.RelationshipType) []file.Coordinates {
	var coordinates []file.Coordinates
	for _, relationship := range s.RelationshipsForPackage(p, rt...) {
		cords := extractCoordinates(relationship)
		coordinates = append(coordinates, cords...)
	}
	return coordinates
}

// 此帮助函数从单个关系对象中提取文件坐标。
func extractCoordinates(relationship artifact.Relationship) (results []file.Coordinates) {
	if coordinates, exists := relationship.From.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	if coordinates, exists := relationship.To.(file.Coordinates); exists {
		results = append(results, coordinates)
	}

	return results
}
