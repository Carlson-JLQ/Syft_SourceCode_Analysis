package cataloging

import "github.com/anchore/syft/syft/source"

// SearchConfig 结构体用于配置包搜索的范围。
// Scope (类型为 source.Scope)： 指定搜索的范围。该类型来自导包 source。
type SearchConfig struct {
	Scope source.Scope `yaml:"scope" json:"scope" mapstructure:"scope"`
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		Scope: source.SquashedScope,
	}
}

func (c SearchConfig) WithScope(scope source.Scope) SearchConfig {
	c.Scope = scope
	return c
}
