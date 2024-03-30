/*
Package source provides an abstraction to allow a user to loosely define a data source to catalog and expose a common interface that
catalogers and use explore and analyze data from the data source. All valid (cataloggable) data sources are defined
within this package.
*/
//它为用户提供了一种定义数据源的抽象，并公开了一个通用接口，允许不同部分（编目器和用户）与各种数据源交互，
//而无需了解它们的具体细节。
package source

import (
	"errors"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

// artifact.Identifiable: 表示数据源具有标识符。
// FileResolver(Scope) (file.Resolver, error): 接受一个 Scope 参数并返回一个 file.Resolver 对象和一个错误（如果有）。file.Resolver 可能用于根据提供的范围（例如，只读、可写）访问数据源中的文件。
// Describe() Description: 返回一个 Description 对象，该对象可能包含有关数据源的元数据。
// io.Closer: 此接口表明数据源可以关闭，从而释放资源
type Source interface {
	artifact.Identifiable
	FileResolver(Scope) (file.Resolver, error)
	Describe() Description
	io.Closer
}

type emptySource struct {
	description Description
}

// 此函数接受一个 Description 对象并返回一个新的 emptySource 实例，该实例使用该描述进行了初始化。
func FromDescription(d Description) Source {
	return &emptySource{
		description: d,
	}
}

func (e emptySource) ID() artifact.ID {
	return artifact.ID(e.description.ID)
}

func (e emptySource) FileResolver(_ Scope) (file.Resolver, error) {
	return nil, errors.New("no file resolver available for description-only source")
}

func (e emptySource) Describe() Description {
	return e.description
}

func (e emptySource) Close() error {
	return nil // no-op
}
