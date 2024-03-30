package cpe

import (
	"fmt"
	"sort"
)

// Merge returns unique SourcedCPEs that are found in A or B
// Two SourcedCPEs are identical if their source and normalized string are identical
//合并来自 a 和 b 切片中的唯一 CPE 数据。
//两个 CPE 被视为相同，当且仅当它们的来源 (Source) 和经过规范化后的字符串 (Attributes.BindToFmtString()) 相同。
//合并后按来源 (Source) 和特异性 (specificity) 进行排序。

func Merge(a, b []CPE) []CPE {
	var result []CPE
	dedupe := make(map[string]CPE)
	key := func(scpe CPE) string {
		return fmt.Sprintf("%s:%s", scpe.Source.String(), scpe.Attributes.BindToFmtString())
	}
	for _, s := range a {
		dedupe[key(s)] = s
	}
	for _, s := range b {
		dedupe[key(s)] = s
	}
	for _, val := range dedupe {
		result = append(result, val)
	}
	sort.Sort(BySourceThenSpecificity(result))
	return result
}

//定义结果容器 result (类型为 []CPE)，用于存储合并后的 CPE 数据。
//创建哈希表 dedupe (类型为 map[string]CPE)，用于去重。键为经过格式化的字符串 (来源 + 规范化后的属性字符串)，值则为对应的 CPE 对象。
//定义键生成函数 key(scpe CPE):
//将来源 (scpe.Source.String()) 和经过规范化后的属性字符串 (scpe.Attributes.BindToFmtString()) 使用 fmt.Sprintf 连接成一个字符串作为键。
//遍历 a 切片中的每个 CPE (s):
//使用 key 函数生成键，并将 CPE 对象 (s) 作为值添加到哈希表 dedupe 中。
//遍历 b 切片中的每个 CPE (s):
//重复步骤 4 的操作，将 b 中的 CPE 添加到哈希表中，如果有重复的键，则会覆盖 a 中的 CPE。
//遍历哈希表 dedupe 中的所有值 (val):
//将哈希表中的 CPE 对象添加到结果容器 result 中。
//使用 sort.Sort 函数对 result 进行排序，排序规则为 BySourceThenSpecificity (来源然后特异性)。
//返回合并并排序后的 CPE 数据 (result).
