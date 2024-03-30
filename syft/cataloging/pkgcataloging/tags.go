package pkgcataloging

// 该代码定义了 pkgcataloging 包中用于标识包类型和适用场景的常量
const (
	// InstalledTag is to identify packages found to be positively installed.
	//InstalledTag: 用于标识已确认安装的包。
	InstalledTag = "installed"

	// DeclaredTag is to identify packages described but not necessarily installed.
	//DeclaredTag: 用于标识被描述但不一定安装的包。
	DeclaredTag = "declared"

	// ImageTag indicates the cataloger should be used when cataloging images.
	//ImageTag: 用于标识适用于镜像编制器的目录编制器。
	ImageTag = "image"

	// DirectoryTag indicates the cataloger should be used when cataloging directories.
	//DirectoryTag: 用于标识适用于目录编制器的目录编制器
	DirectoryTag = "directory"

	// PackageTag should be used to identify catalogers that are package-based.
	//PackageTag: 用于标识基于包的目录编制器。
	PackageTag = "package"

	// OSTag should be used to identify catalogers that cataloging OS packages.
	//OSTag: 用于标识用于操作系统包编制器的目录编制器。
	OSTag = "os"

	// LanguageTag should be used to identify catalogers that cataloging language-specific packages.
	//LanguageTag: 用于标识用于特定语言包编制器的目录编制器
	LanguageTag = "language"
)
