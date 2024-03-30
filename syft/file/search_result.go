package file

//该代码定义了一个名为 SearchResult 的结构体，用于表示文件搜索结果。
import (
	"fmt"
)

// Classification (string): 搜索结果的分类 (例如，许可证、URL 等)。
// LineNumber (int64): 匹配项所在的行号 (如果存在)。
// LineOffset (int64): 匹配项在行中的偏移量 (从 0 开始)。
// SeekPosition (int64): 文件中匹配项的字节偏移量。
// Length (int64): 匹配项的长度 (字节数)。
// Value (string, optional): 匹配项的值 (可省略)。
type SearchResult struct {
	Classification string `json:"classification"`
	LineNumber     int64  `json:"lineNumber"`
	LineOffset     int64  `json:"lineOffset"`
	SeekPosition   int64  `json:"seekPosition"`
	Length         int64  `json:"length"`
	Value          string `json:"value,omitempty"`
}

func (s SearchResult) String() string {
	return fmt.Sprintf("SearchResult(classification=%q seek=%q length=%q)", s.Classification, s.SeekPosition, s.Length)
}
