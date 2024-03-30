package cli

import (
	"io"
	"os"

	cranecmd "github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/cmd/syft/internal/commands"
)

// Application constructs the `syft packages` command and aliases the root command to `syft packages`.
// It is also responsible for organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.
// `RunE` is the earliest that the complete application configuration can be loaded.

// Application 函数:
// 创建 clio.Application 对象，用于构建 syft 命令行工具。
// 定义并添加 scan, packages (其实是 scan 的别名)、cataloger, attest, convert 等子命令。
// 添加版本信息 (clio.VersionCommand) 和登录命令 (cranecmd.NewCmdAuthLogin)。
func Application(id clio.Identification) clio.Application {
	app, _ := create(id, os.Stdout)
	return app
}

// Command returns the root command for the syft CLI application. This is useful for embedding the entire syft CLI
// into an existing application.
// Command 函数:
// 返回根命令 (cobra.Command)，方便将整个 syft CLI 嵌入到其他应用程序中。
func Command(id clio.Identification) *cobra.Command {
	_, cmd := create(id, os.Stdout)
	return cmd
}

// create 函数:
// 根据标识 (id) 和输出流 (out) 创建应用程序配置 (clioCfg)。
// 构建 clio.Application 对象 (app)。
// 按照依赖关系顺序创建子命令，例如 scan 命令需要先于 packages 命令创建 (因为 packages 是 scan 的别名)。
// 将所有子命令添加到根命令 (rootCmd) 中。
func create(id clio.Identification, out io.Writer) (clio.Application, *cobra.Command) {
	clioCfg := internal.AppClioSetupConfig(id, out)

	app := clio.New(*clioCfg)

	// since root is aliased as the packages cmd we need to construct this command first
	// we also need the command to have information about the `root` options because of this alias
	scanCmd := commands.Scan(app)

	// root is currently an alias for the scan command
	rootCmd := commands.Root(app, scanCmd)

	// add sub-commands
	rootCmd.AddCommand(
		scanCmd,
		commands.Packages(app, scanCmd), // this is currently an alias for the scan command
		commands.Cataloger(app),
		commands.Attest(app),
		commands.Convert(app),
		clio.VersionCommand(id),
		cranecmd.NewCmdAuthLogin(id.Name), // syft login uses the same command as crane
	)
	//这段注释解释了为什么没有显式设置输出流 (writer) 的原因。
	//
	//我们本想使用 rootCmd.SetOut(out) 让 Cobra 库将输出定向到我们提供的 writer 对象。
	//但是这样做会导致本来应该输出到标准错误流 (stderr) 的弃用警告信息，却通过 writer 输出到标准输出流 (stdout)。
	//这显然不是 Cobra 期望的行为，相关 Bug 可以参考 https://github.com/spf13/cobra/releases.
	//希望在未来的版本中，Cobra 能修复此功能。
	// note: we would direct cobra to use our writer explicitly with rootCmd.SetOut(out) , however this causes
	// deprecation warnings to be shown to stdout via the writer instead of stderr. This is unfortunate since this
	// does not appear to be the correct behavior on cobra's part https://github.com/spf13/cobra/issues/1708 .
	// In the future this functionality should be restored.

	return app, rootCmd
}
