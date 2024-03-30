package cpe

//此处导入了 Go 语言标准库的 sort 包，用于对切片进行排序。
import "sort"

// BySourceThenSpecificity 类型是 []CPE (CPE 数据切片) 的别名，用于实现 sort.Interface 接口，从而可以在排序算法中使用。
type BySourceThenSpecificity []CPE

// 实现 sort.Interface 接口的 Len() 方法，返回切片 b 的长度。
func (b BySourceThenSpecificity) Len() int {
	return len(b)
}

// 实现 sort.Interface 接口的 Less() 方法，比较切片 b 中索引为 i 和 j 的元素，并返回 bool 值。
// 该方法首先定义了一个映射 sourceOrder，用于根据 CPE 数据来源的优先级进行排序。例如，NVDDictionaryLookupSource (从 NVD 词典查找) 的优先级最高 (1)，其次是 DeclaredSource (声明的) 和 GeneratedSource (生成的)。
// 然后，它定义了一个 getRank 函数，根据来源类型从 sourceOrder 映射中获取优先级排名。如果没有找到对应的来源类型，则返回一个较低的值 (4)。
// 比较两个 CPE 数据的来源优先级 (rankI 和 rankJ)，如果优先级不同，则优先级高的排在前面。
// 如果优先级相同，则调用 isMoreSpecific 函数 (未在提供的代码中) 比较两个 CPE 数据的特异性，更特异的 CPE 数据排在前面。
// (b BySourceThenSpecificity) Swap(i, j int)： 实现 sort.Interface 接口的 Swap() 方法，交换切片 b 中索引为 i 和 j 的元素。
func (b BySourceThenSpecificity) Less(i, j int) bool {
	sourceOrder := map[Source]int{
		NVDDictionaryLookupSource: 1,
		DeclaredSource:            2,
		GeneratedSource:           3,
	}

	getRank := func(source Source) int {
		if rank, exists := sourceOrder[source]; exists {
			return rank
		}
		return 4 // Sourced we don't know about can't be assigned special priority, so
		// are considered ties.
	}
	iSource := b[i].Source
	jSource := b[j].Source
	rankI, rankJ := getRank(iSource), getRank(jSource)
	if rankI != rankJ {
		return rankI < rankJ
	}

	return isMoreSpecific(b[i].Attributes, b[j].Attributes)
}

// (b BySourceThenSpecificity) Swap(i, j int)： 实现 sort.Interface 接口的 Swap() 方法，交换切片 b 中索引为 i 和 j 的元素。
func (b BySourceThenSpecificity) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

var _ sort.Interface = (*BySourceThenSpecificity)(nil)

//
//该代码定义了一种根据来源和特异性对 CPE 数据进行排序的规则。排序的依据依次为：
//
//来源优先级：
//从 NVD 词典查找的 CPE 数据优先级最高。
//其次是声明的 CPE 数据。
//最后是生成的 CPE 数据。
//特异性：
//如果来源优先级相同，则比较 CPE 数据的特异性。更特异的 CPE 数据 (例如，包含更多细节) 将排在前面。
