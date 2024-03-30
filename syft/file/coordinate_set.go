package file

import (
	"sort"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/scylladb/go-set/strset"
)

// 该代码定义了 CoordinateSet 结构体，用于表示一组文件坐标的集合。
// CoordinateSet: 内部使用一个哈希表 (map) 存储 Coordinates 结构体。
// 哈希表的键 (key) 为 Coordinates 结构体，表示文件的位置信息。
// 哈希表的元素 (value) 为 struct{}{} 类型，该类型仅用于占位，没有实际意义。
type CoordinateSet struct {
	set map[Coordinates]struct{}
}

// 创建一个新的 CoordinateSet 实例，可以接受可选的 Coordinates 参数进行初始化。
func NewCoordinateSet(coordinates ...Coordinates) (s CoordinateSet) {
	for _, l := range coordinates {
		s.Add(l)
	}

	return s
}

func (s *CoordinateSet) Add(coordinates ...Coordinates) {
	if s.set == nil {
		s.set = make(map[Coordinates]struct{})
	}
	for _, l := range coordinates {
		s.set[l] = struct{}{}
	}
}

func (s CoordinateSet) Remove(coordinates ...Coordinates) {
	if s.set == nil {
		return
	}
	for _, l := range coordinates {
		delete(s.set, l)
	}
}

func (s CoordinateSet) Contains(l Coordinates) bool {
	if s.set == nil {
		return false
	}
	_, ok := s.set[l]
	return ok
}

// 返回集合中所有文件 (根据 RealPath 属性) 的路径列表，并按升序排序。
func (s CoordinateSet) Paths() []string {
	if s.set == nil {
		return nil
	}

	paths := strset.New()
	for _, c := range s.ToSlice() {
		paths.Add(c.RealPath)
	}
	pathSlice := paths.List()
	sort.Strings(pathSlice)
	return pathSlice
}

// 将集合转换为切片 ([]Coordinates)，并按 RealPath 和 FileSystemID 进行排序。
// 排序规则是先比较 RealPath，如果 RealPath 相同，则比较 FileSystemID。
func (s CoordinateSet) ToSlice() []Coordinates {
	if s.set == nil {
		return nil
	}
	coordinates := make([]Coordinates, len(s.set))
	idx := 0
	for v := range s.set {
		coordinates[idx] = v
		idx++
	}
	sort.SliceStable(coordinates, func(i, j int) bool {
		if coordinates[i].RealPath == coordinates[j].RealPath {
			return coordinates[i].FileSystemID < coordinates[j].FileSystemID
		}
		return coordinates[i].RealPath < coordinates[j].RealPath
	})
	return coordinates
}

// 计算集合的哈希值，仅考虑 Coordinates 结构体本身的信息 (不包含哈希表本身)。
func (s CoordinateSet) Hash() (uint64, error) {
	return hashstructure.Hash(s.ToSlice(), hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
}
