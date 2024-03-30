package file

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/internal/log"
)

// 该代码定义了 LocationSet 结构体，用于表示一组文件位置的集合。
// LocationSet 内部使用一个哈希表 (map) 存储文件位置信息。
// 哈希表的键 (key) 为 LocationData 结构体，包含文件的真实路径 (RealPath) 和文件系统标识 (FileSystemID)。
// 哈希表的元素 (value) 为 LocationMetadata 结构体，包含可选的注释信息 (Annotations)。
type LocationSet struct {
	set map[LocationData]LocationMetadata
}

// LocationSet的新增
func NewLocationSet(locations ...Location) (s LocationSet) {
	for _, l := range locations {
		s.Add(l)
	}

	return s
}

func (s *LocationSet) Add(locations ...Location) {
	if s.set == nil {
		s.set = make(map[LocationData]LocationMetadata)
	}
	for _, l := range locations {
		if m, ok := s.set[l.LocationData]; ok {
			err := m.merge(l.LocationMetadata)
			if err != nil {
				log.Debugf("partial merge of location metadata: %+v", err)
			}
			s.set[l.LocationData] = m
		} else {
			s.set[l.LocationData] = l.LocationMetadata
		}
	}
}

// 从集合中删除给定的 Location
//locations 是参数名，可以是任意有效的标识符。
//... 表示这是一个可变参数列表，可以接受任意数量的参数。
//Location 是参数类型，表示每个参数都必须是 Location 类型。
func (s LocationSet) Remove(locations ...Location) {
	if s.set == nil {
		return
	}
	for _, l := range locations {
		delete(s.set, l.LocationData)
	}
}

// 检查集合中是否包含指定的 Location
func (s LocationSet) Contains(l Location) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[l.LocationData]
	return ok
}

// 将集合转换为切片 ([]Location)，并按某种规则排序。
func (s LocationSet) ToSlice() []Location {
	if s.set == nil {
		return nil
	}
	locations := make([]Location, len(s.set))
	idx := 0
	for dir := range s.set {
		locations[idx] = Location{
			LocationData:     dir,
			LocationMetadata: s.set[dir],
		}
		idx++
	}
	sort.Sort(Locations(locations))
	return locations
}

// 返回一个包含集合中所有文件坐标 (Coordinates) 的 CoordinateSet 实例。
func (s *LocationSet) CoordinateSet() CoordinateSet {
	if s.set == nil {
		return NewCoordinateSet()
	}
	set := NewCoordinateSet()
	for l := range s.set {
		set.Add(l.Coordinates)
	}
	return set
}

// 判断集合是否为空。
func (s *LocationSet) Empty() bool {
	if s.set == nil {
		return true
	}
	return len(s.set) == 0
}

// 计算集合的哈希值，仅考虑文件的真实路径，不包含访问路径和文件系统标识。
func (s LocationSet) Hash() (uint64, error) {
	// access paths and filesystem IDs are not considered when hashing a location set, only the real paths
	return hashstructure.Hash(s.CoordinateSet().Paths(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}
