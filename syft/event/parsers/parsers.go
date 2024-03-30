/*
Package parsers provides parser helpers to extract payloads for each event type that the syft library publishes onto the event bus.
*/
package parsers

//该代码提供了用于解析 Syft 库发布到事件总线 (event bus) 的事件的解析器助手函数。
import (
	"fmt"
	"io"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
)

// 主要功能:
// 提取每个事件类型的有效载荷 (payload)。
// 验证事件类型是否正确。
// 从事件中提取特定字段的值。
// 处理解析错误

// 定义了 ErrBadPayload 错误类型，用于表示事件有效载荷格式错误。
type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field=%q: %q", string(e.Type), e.Field, e.Value)
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

// checkEventType 函数用于校验事件类型是否匹配预期。
func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

//每个解析函数都遵循类似的模式：
//首先校验事件类型。
//然后尝试从事件中提取所需字段的值，并进行类型检查。
//最后根据提取到的值返回解析结果，或是在遇到错误时返回错误信息。

// 解析文件索引开始事件，提取索引路径和进度条对象。
func ParseFileIndexingStarted(e partybus.Event) (string, progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.FileIndexingStarted); err != nil {
		return "", nil, err
	}

	path, ok := e.Source.(string)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return "", nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return path, prog, nil
}

// 解析编目器任务开始事件，提取进度条对象和任务信息。
func ParseCatalogerTaskStarted(e partybus.Event) (progress.StagedProgressable, *monitor.GenericTask, error) {
	if err := checkEventType(e.Type, event.CatalogerTaskStarted); err != nil {
		return nil, nil, err
	}

	var mon progress.StagedProgressable

	source, ok := e.Source.(monitor.GenericTask)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	mon, ok = e.Value.(progress.StagedProgressable)
	if !ok {
		mon = nil
	}

	return mon, &source, nil
}

// 解析 SBOM 证明开始事件，提取读取器、进度条对象和任务信息。
func ParseAttestationStartedEvent(e partybus.Event) (io.Reader, progress.Progressable, *monitor.GenericTask, error) {
	if err := checkEventType(e.Type, event.AttestationStarted); err != nil {
		return nil, nil, nil, err
	}

	source, ok := e.Source.(monitor.GenericTask)
	if !ok {
		return nil, nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	sp, ok := e.Value.(*monitor.ShellProgress)
	if !ok {
		return nil, nil, nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return sp.Reader, sp.Progressable, &source, nil
}

// CLI event types
// 针对 CLI (命令行界面) 事件类型的解析函数：
// ParseCLIAppUpdateAvailable: 解析应用程序更新可用事件，提取新版本和当前版本信息。
// ParseCLIReport: 解析 CLI 报告事件，提取上下文信息和报告内容。
// ParseCLINotification: 解析 CLI 通知事件，提取上下文信息和通知内容。
type UpdateCheck struct {
	New     string
	Current string
}

// ParseCLIAppUpdateAvailable: 解析应用程序更新可用事件，提取新版本和当前版本信息。
func ParseCLIAppUpdateAvailable(e partybus.Event) (*UpdateCheck, error) {
	if err := checkEventType(e.Type, event.CLIAppUpdateAvailable); err != nil {
		return nil, err
	}

	updateCheck, ok := e.Value.(UpdateCheck)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &updateCheck, nil
}

// ParseCLIReport: 解析 CLI 报告事件，提取上下文信息和报告内容。
func ParseCLIReport(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLIReport); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}

// ParseCLINotification: 解析 CLI 通知事件，提取上下文信息和通知内容。
func ParseCLINotification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLINotification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}
