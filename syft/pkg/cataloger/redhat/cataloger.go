/*
Package redhat provides a concrete DBCataloger implementation relating to packages within the RedHat linux distribution.
*/
package redhat

//导入了一些必要的库，用于数据库交互（database/sql）、
//日志记录（github.com/anchore/syft/internal/log）、
//软件包处理（github.com/anchore/syft/syft/pkg）以及
//通用编目器（github.com/anchore/syft/syft/pkg/cataloger/generic
import (
	"database/sql"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDBCataloger 函数:
// 此函数创建一个新的编目器，用于处理存储在数据库（可能是 RPM 数据库）中的 Red Hat 软件包。
// 它会检查 sqlite 驱动程序是否可用（用于访问 RPM 数据库）。
// 如果不可用，则会记录一条警告，指示可能存在与较新数据库相关的问题。
// 它创建一个名为 “rpm-db-cataloger” 的通用编目器。
// 它使用基于文件 glob 的两个解析器配置编目器:
// parseRpmDB: 此函数可能解析 RPM 数据库中的条目。
// parseRpmManifest: 此函数可能解析数据库中的包清单。
// 两个解析器都与特定的 glob 模式相关联（pkg.RpmDBGlob 和潜在的清单模式）。
// NewDBCataloger returns a new RPM DB cataloger object.
func NewDBCataloger() pkg.Cataloger {
	// check if a sqlite driver is available
	if !isSqliteDriverAvailable() {
		log.Warnf("sqlite driver is not available, newer RPM databases might not be cataloged")
	}

	return generic.NewCataloger("rpm-db-cataloger").
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob)
}

// NewArchiveCataloger 函数:
// 此函数创建一个新的编目器，用于处理来自存档文件（可能是 RPM 文件）的 Red Hat 软件包。
// 它创建一个名为 “rpm-archive-cataloger” 的通用编目器。
// 它使用单个解析器配置编目器:
// parseRpmArchive: 此函数可能解析来自单个 RPM 存档文件的信息。
// 解析器与通用 glob 模式 **/*.rpm 相关联，该模式以任何子目录中的所有 .rpm 扩展名文件为目标。
// NewArchiveCataloger returns a new RPM file cataloger object.
func NewArchiveCataloger() pkg.Cataloger {
	return generic.NewCataloger("rpm-archive-cataloger").
		WithParserByGlobs(parseRpmArchive, "**/*.rpm")
}

// isSqliteDriverAvailable 函数:
// 此辅助函数检查系统中是否可用 sqlite 数据库驱动程序。
// 它尝试打开与内存中 SQLite 数据库的连接。
// 如果连接成功（没有错误），则返回 true，指示驱动程序可用。
func isSqliteDriverAvailable() bool {
	_, err := sql.Open("sqlite", ":memory:")
	return err == nil
}
