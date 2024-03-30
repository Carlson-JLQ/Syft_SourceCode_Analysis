package cataloging

// ArchiveSearchConfig 结构体用于配置存档搜索行为。
// IncludeIndexedArchives (类型为 bool)： 指定是否将已索引的存档包含在搜索结果中。
// IncludeUnindexedArchives (类型为 bool)： 指定是否将未索引的存档包含在搜索结果中。
type ArchiveSearchConfig struct {
	IncludeIndexedArchives   bool `yaml:"include-indexed-archives" json:"include-indexed-archives" mapstructure:"include-indexed-archives"`
	IncludeUnindexedArchives bool `yaml:"include-unindexed-archives" json:"include-unindexed-archives" mapstructure:"include-unindexed-archives"`
}

// DefaultArchiveSearchConfig()： 返回一个默认的 ArchiveSearchConfig 配置。
// 默认情况下，已索引的存档将被包含在搜索结果中，而未索引的存档将被排除在外。
func DefaultArchiveSearchConfig() ArchiveSearchConfig {
	return ArchiveSearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
	}
}

// 更新 IncludeIndexedArchives 配置项。
func (c ArchiveSearchConfig) WithIncludeIndexedArchives(include bool) ArchiveSearchConfig {
	c.IncludeIndexedArchives = include
	return c
}

// 更新 IncludeUnindexedArchives 配置项。
func (c ArchiveSearchConfig) WithIncludeUnindexedArchives(include bool) ArchiveSearchConfig {
	c.IncludeUnindexedArchives = include
	return c
}
