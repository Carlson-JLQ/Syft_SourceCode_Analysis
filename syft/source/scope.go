package source

import "strings"

// 范围 (Scope) 指示了源对象应该如何编目，或者应该从哪些角度进行编目。
// Scope indicates "how" or from "which perspectives" the source object should be cataloged from.
type Scope string

// UnknownScope: 默认范围，表示未知的编目范围。
// SquashedScope: 指示只编目从压缩文件系统 (squashed filesystem) 可见的的内容。换句话说，只分析容器运行时可见的内容。
// AllLayersScope: 指示编目所有层 (layers) 的内容，而不考虑容器运行时是否可见。容器镜像通常由多个层组成，AllLayersScope 会分析所有层的软件包信息。
const (
	// UnknownScope is the default scope
	UnknownScope Scope = "unknown-scope"
	// SquashedScope indicates to only catalog content visible from the squashed filesystem representation (what can be seen only within the container at runtime)
	SquashedScope Scope = "squashed"
	// AllLayersScope indicates to catalog content on all layers, regardless if it is visible from the container at runtime.
	AllLayersScope Scope = "all-layers"
)

// AllScopes is a slice containing all possible scope options
var AllScopes = []Scope{
	SquashedScope,
	AllLayersScope,
}

// ParseScope returns a scope as indicated from the given string.
func ParseScope(userStr string) Scope {
	switch strings.ToLower(userStr) {
	case SquashedScope.String():
		return SquashedScope
	case "alllayers", AllLayersScope.String():
		return AllLayersScope
	}
	return UnknownScope
}

func (o Scope) String() string {
	return string(o)
}
