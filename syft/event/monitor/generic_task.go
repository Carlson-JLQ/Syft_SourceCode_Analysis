package monitor

//该代码定义了用于表示监控任务的几个结构体
import (
	"io"

	"github.com/wagoodman/go-progress"
)

// ShellProgress: 代表一个带有进度的 shell 命令执行过程。
// 包含两个字段：
// io.Reader: 用于读取 shell 命令的输出。
// progress.Progressable: 提供进度条功能的对象。
type ShellProgress struct {
	io.Reader
	progress.Progressable
}

// Title: 用于定义任务标题的不同状态。
// 包含三个字段：
// Default: 任务的默认标题。
// WhileRunning: 任务正在运行时的标题。
// OnSuccess: 任务成功完成时的标题。
type Title struct {
	Default      string
	WhileRunning string
	OnSuccess    string
}

// GenericTask: 表示一个通用的监控任务。
// 包含多个字段：
// 必需字段
// Title: 任务的标题 (使用 Title 结构体定义)。
// 可选格式化字段
// HideOnSuccess: 任务成功后是否隐藏标题 (默认为 false)。
// HideStageOnSuccess: 任务成功后是否隐藏阶段信息 (默认为 false)。
// 可选字段
// ID: 任务的唯一标识符 (字符串)。
// ParentID: 父任务的标识符 (字符串)。
// Context: 任务的上下文信息 (字符串)。
type GenericTask struct {

	// required fields

	Title Title

	// optional format fields

	HideOnSuccess      bool
	HideStageOnSuccess bool

	// optional fields

	ID       string
	ParentID string
	Context  string
}
