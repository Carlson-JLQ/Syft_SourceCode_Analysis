package pkgcataloging

//该代码定义了 pkgcataloging 包中用于指定包选择条件的 SelectionRequest 结构体及其相关函数
import (
	"strings"
)

// SelectionRequest 结构体用于表示一个包选择的请求。
// DefaultNamesOrTags： 默认的包名或标签列表 (类型为 []string)。
// SubSelectTags： 子选择标签列表 (类型为 []string)。
// AddNames： 要额外添加的包名列表 (类型为 []string)。
// RemoveNamesOrTags： 要移除的包名或标签列表 (类型为 []string)。
type SelectionRequest struct {
	DefaultNamesOrTags []string `json:"default,omitempty"`
	SubSelectTags      []string `json:"selection,omitempty"`
	AddNames           []string `json:"addition,omitempty"`
	RemoveNamesOrTags  []string `json:"removal,omitempty"`
}

// NewSelectionRequest()： 创建一个空的 SelectionRequest 实例
func NewSelectionRequest() SelectionRequest {
	return SelectionRequest{}
}

// 根据表达式来构建 SelectionRequest。
// 该函数首先清理表达式列表 (cleanSelection)。
// 然后，它遍历每个表达式：
// 以 + 开头的表达式表示要添加的包，会调用 WithAdditions 函数。
// 以 - 开头的表达式表示要移除的包，会调用 WithRemovals 函数。
// 其他表达式表示子选择标签，会调用 WithSubSelections 函数。
func (s SelectionRequest) WithExpression(expressions ...string) SelectionRequest {
	expressions = cleanSelection(expressions)
	for _, expr := range expressions {
		switch {
		case strings.HasPrefix(expr, "+"):
			s = s.WithAdditions(strings.TrimPrefix(expr, "+"))
		case strings.HasPrefix(expr, "-"):
			s = s.WithRemovals(strings.TrimPrefix(expr, "-"))
		default:
			s = s.WithSubSelections(expr)
		}
	}
	return s
}

// 其他函数用于设置 SelectionRequest 的特定部分：
// WithDefaults(nameOrTags ...string)： 设置默认的包名或标签。
// WithSubSelections(tags ...string)： 设置子选择标签。
// WithAdditions(names ...string)： 设置要额外添加的包名。
// WithRemovals(nameOrTags ...string)： 设置要移除的包名或标签。
func (s SelectionRequest) WithDefaults(nameOrTags ...string) SelectionRequest {
	s.DefaultNamesOrTags = append(s.DefaultNamesOrTags, nameOrTags...)
	return s
}

func (s SelectionRequest) WithSubSelections(tags ...string) SelectionRequest {
	s.SubSelectTags = append(s.SubSelectTags, tags...)
	return s
}

func (s SelectionRequest) WithAdditions(names ...string) SelectionRequest {
	s.AddNames = append(s.AddNames, names...)
	return s
}

func (s SelectionRequest) WithRemovals(nameOrTags ...string) SelectionRequest {
	s.RemoveNamesOrTags = append(s.RemoveNamesOrTags, nameOrTags...)
	return s
}

// 清理表达式列表。
// 该函数将每个表达式中的空格去掉，并过滤掉空字符串。
func cleanSelection(tags []string) []string {
	var cleaned []string
	for _, tag := range tags {
		for _, t := range strings.Split(tag, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			cleaned = append(cleaned, t)
		}
	}
	return cleaned
}
