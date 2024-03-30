package monitor

//这段代码定义了用于监控编目任务进度的结构和常量。

//代码依赖 github.com/wagoodman/go-progress 包，该包可能提供了进度条相关的功能。
import (
	"github.com/wagoodman/go-progress"
)

// CatalogerTaskProgress：用于表示编目任务的进度信息。
// 嵌入了 progress.AtomicStage 和 progress.Manual 类型，可能分别用于表示原子阶段（无法被其他阶段并行进行的阶段）和手动控制的进度。
const (
	TopLevelCatalogingTaskID = "cataloging"
	PackageCatalogingTaskID  = "package-cataloging"
)

type CatalogerTaskProgress struct {
	*progress.AtomicStage
	*progress.Manual
}
