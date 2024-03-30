package pkgcataloging

//用于管理包目录编制器的引用。
import "github.com/anchore/syft/syft/pkg"

// CatalogerReference结构体表示对包目录编制器的引用：
// Cataloger字段： 存储包目录编制器实例。
// AlwaysEnabled字段： 布尔值，表示该目录编制器是否始终启用。
// Tags字段： 字符串切片，存储与该引用相关的标签。
type CatalogerReference struct {
	Cataloger     pkg.Cataloger
	AlwaysEnabled bool
	Tags          []string
}

// NewCatalogerReference()函数： 创建新的CatalogerReference实例：
// 接受cataloger（包目录编制器实例）和tags（标签列表）作为参数。
// 返回一个新的CatalogerReference实例，其中AlwaysEnabled字段默认为false。
func NewCatalogerReference(cataloger pkg.Cataloger, tags []string) CatalogerReference {
	return CatalogerReference{
		Cataloger: cataloger,
		Tags:      tags,
	}
}

// NewAlwaysEnabledCatalogerReference()函数： 创建新的CatalogerReference实例：
// 接受cataloger（包目录编制器实例）作为参数。
// 返回一个新的CatalogerReference实例，AlwaysEnabled字段被设置为true。
func NewAlwaysEnabledCatalogerReference(cataloger pkg.Cataloger) CatalogerReference {
	return CatalogerReference{
		Cataloger:     cataloger,
		AlwaysEnabled: true,
	}
}
