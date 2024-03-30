package file

// 该代码定义了一个枚举类型 Selection，用于指定文件选择方式。
const (
	//表示不选择任何文件
	NoFilesSelection Selection = "none"
	//表示仅选择属于特定包的文件，其值为
	FilesOwnedByPackageSelection Selection = "owned-by-package"
	//表示选择所有文件
	AllFilesSelection Selection = "all"
)

type Selection string
