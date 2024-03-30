package main

//导入 clio 包，用于构建命令行应用程序。
import (
	_ "modernc.org/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli"
	"github.com/anchore/syft/cmd/syft/internal"
)

// applicationName: 定义应用程序名称为小写字母的常量 (syft)。
// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "syft"

// version, buildDate, gitCommit, gitDescription:
// 存储应用程序版本、构建日期、Git 提交哈希和 Git 描述信息的变量。它们可能在构建过程中使用构建时参数填充。internal.NotProvided 是占位符，表示信息尚未设置
// all variables here are provided as build-time arguments, with clear default values
var (
	version        = internal.NotProvided
	buildDate      = internal.NotProvided
	gitCommit      = internal.NotProvided
	gitDescription = internal.NotProvided
)

// main 函数:
// 程序的入口点。
// cli.Application: 来自 clio 包的函数，用于创建新的 CLI 应用程序实例。
// clio.Identification: 提供应用程序信息的结构，包括导入的变量如 applicationName, version 等。
// app.Run(): 启动应用程序并处理用户提供的命令或参数。
func main() {
	app := cli.Application(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()
}
