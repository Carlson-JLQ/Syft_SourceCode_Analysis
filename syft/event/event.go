/*
Package event provides event types for all events that the syft library published onto the event bus. By convention, for each event
defined here there should be a corresponding event parser defined in the parsers/ child package.
*/
//该代码定义了 Syft 库发布到事件总线 (event bus) 的所有事件类型。事件总线是一种用于组件间通信的机制。
package event

import (
	"github.com/wagoodman/go-partybus"
)

const (
	//事件类型前缀:
	//typePrefix 定义了所有 Syft 库事件类型的通用前缀 ("syft")。
	//cliTypePrefix 定义了仅用于 CLI (命令行界面) 的事件类型的特有前缀 ("syft-cli")。
	typePrefix    = "syft"
	cliTypePrefix = typePrefix + "-cli"
	//事件定义: 代码通过 partybus.EventType 类型定义了多个事件类型，每个事件类型都有一个描述性的名称。

	// Events from the syft library

	// FileIndexingStarted is a partybus event that occurs when the directory resolver begins indexing a filesystem
	//当目录解析器开始索引文件系统时触发的事件。
	FileIndexingStarted partybus.EventType = typePrefix + "-file-indexing-started-event"

	// AttestationStarted is a partybus event that occurs when starting an SBOM attestation process
	//当启动 SBOM 证明过程时触发的事件 (SBOM 代表软件材料清单)。
	AttestationStarted partybus.EventType = typePrefix + "-attestation-started-event"

	// CatalogerTaskStarted is a partybus event that occurs when starting a task within a cataloger
	//当启动编目器中的某个任务时触发的事件。
	CatalogerTaskStarted partybus.EventType = typePrefix + "-cataloger-task-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	//当应用程序更新可用时 (仅限 CLI) 触发的事件。
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	//当分析结果准备好最终呈现到标准输出 (stdout) 时 (仅限 CLI) 触发的事件。
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	//当辅助信息准备好呈现到标准错误输出 (stderr) 时 (仅限 CLI) 触发的事件。
	CLINotification partybus.EventType = cliTypePrefix + "-notification"
)
