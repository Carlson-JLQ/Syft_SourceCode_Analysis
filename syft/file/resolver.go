package file

import (
	"context"
	"io"
)

// Resolver 是最顶层的接口，它包含了其他几个子接口的功能。
// 子接口分别负责文件内容、路径、位置和元数据的解析。
// Resolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type Resolver interface {
	ContentResolver
	PathResolver
	LocationResolver
	MetadataResolver
}

// 负责根据文件位置 (Location) 获取文件内容 (可读流 io.ReadCloser)。
// ContentResolver knows how to get file content for a given Location
type ContentResolver interface {
	FileContentsByLocation(Location) (io.ReadCloser, error)
}

// 负责根据文件位置 (Location) 获取文件元数据 (Metadata)。
type MetadataResolver interface {
	FileMetadataByLocation(Location) (Metadata, error)
}

// 负责根据路径或 glob 模式获取文件位置 (Location)。
// PathResolver knows how to get a Location for given string paths and globs
type PathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - returns locations for any file or directory
	//检查给定路径是否存在于数据源中 (并进行完整的符号链接解析)。
	HasPath(string) bool

	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches).
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - only returns locations to files (NOT directories)
	//根据给定路径 (可以有多个) 获取文件引用集合 (只返回文件，不包含目录)。
	FilesByPath(paths ...string) ([]Location, error)

	// FilesByGlob fetches a set of file references for the given glob matches
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - full symlink resolution should be performed on all requests
	// - if multiple paths to the same file are found, the best single match should be returned
	// - only returns locations to files (NOT directories)
	//根据给定 glob 模式获取匹配的文件引用集合 (只返回文件，不包含目录)。
	FilesByGlob(patterns ...string) ([]Location, error)

	// FilesByMIMEType fetches a set of file references which the contents have been classified as one of the given MIME Types.
	//根据给定 MIME 类型获取文件引用集合 (文件内容需要事先进行分类)。
	FilesByMIMEType(types ...string) ([]Location, error)

	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	//相对于给定文件位置，查找指定路径的文件 (用于查找同一层或更低层的文件)。
	RelativeFileByPath(_ Location, path string) *Location
}

// 负责从数据源获取所有文件位置的通道 (不进行符号链接解析，包含文件和目录)。
type LocationResolver interface {
	// AllLocations returns a channel of all file references from the underlying source.
	// The implementation for this may vary, however, generally the following considerations should be made:
	// - NO symlink resolution should be performed on results
	// - returns locations for any file or directory
	AllLocations(ctx context.Context) <-chan Location
}

// 在 Resolver 的基础上增加了写入功能，可以写入文件内容 (需要实现 Write 方法)。
type WritableResolver interface {
	Resolver

	Write(location Location, reader io.Reader) error
}
