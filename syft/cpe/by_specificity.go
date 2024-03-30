package cpe

import (
	"sort"
)

var _ sort.Interface = (*BySpecificity)(nil)

// BySpecificity 类型是 []Attributes (CPE 数据属性切片) 的别名，用于实现 sort.Interface 接口，从而可以在排序算法中使用。
type BySpecificity []Attributes

func (c BySpecificity) Len() int { return len(c) }

func (c BySpecificity) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (c BySpecificity) Less(i, j int) bool {
	return isMoreSpecific(c[i], c[j])
}

// Returns true if i is more specific than j, with some
// tie breaking mechanisms to make sorting equally-specific cpe Attributes
// deterministic.
// isMoreSpecific(i, j Attributes)： 衡量两个 CPE 数据属性的特异性，并返回 bool 值。
// 首先，它调用 weightedCountForSpecifiedFields(i) 和 weightedCountForSpecifiedFields(j) 函数计算每个属性的得分。
// 该函数会检查一些特定的字段 (例如 Part, Vendor, Product) 是否存在，并根据权重进行累加。
// 如果得分不同，则得分更高的属性更特异。
// 如果得分相同，则比较属性的字段长度，较长的字段更特异。
// 如果得分和长度都相同，则按文本顺序进行比较 (使用 BindToFmtString() 方法)。
func isMoreSpecific(i, j Attributes) bool {
	iScore := weightedCountForSpecifiedFields(i)
	jScore := weightedCountForSpecifiedFields(j)

	// check weighted sort first
	if iScore != jScore {
		return iScore > jScore
	}

	// sort longer fields to top
	if countFieldLength(i) != countFieldLength(j) {
		return countFieldLength(i) > countFieldLength(j)
	}

	// if score and length are equal then text sort
	// note that we are not using String from the syft pkg
	// as we are not encoding/decoding this Attributes string so we don't
	// need the proper quoted version of the Attributes.
	return i.BindToFmtString() < j.BindToFmtString()
}

// 计算 CPE 数据属性中各个字段的总长度 (用于比较长度)。
func countFieldLength(cpe Attributes) int {
	return len(cpe.Part + cpe.Vendor + cpe.Product + cpe.Version + cpe.TargetSW)
}

// 根据预定义的规则，计算属性中特定字段存在的加权得分。
func weightedCountForSpecifiedFields(cpe Attributes) int {
	checksForSpecifiedField := []func(cpe Attributes) (bool, int){
		func(cpe Attributes) (bool, int) { return cpe.Part != "", 2 },
		func(cpe Attributes) (bool, int) { return cpe.Vendor != "", 3 },
		func(cpe Attributes) (bool, int) { return cpe.Product != "", 4 },
		func(cpe Attributes) (bool, int) { return cpe.Version != "", 1 },
		func(cpe Attributes) (bool, int) { return cpe.TargetSW != "", 1 },
	}

	weightedCount := 0
	for _, fieldIsSpecified := range checksForSpecifiedField {
		isSpecified, weight := fieldIsSpecified(cpe)
		if isSpecified {
			weightedCount += weight
		}
	}

	return weightedCount
}
