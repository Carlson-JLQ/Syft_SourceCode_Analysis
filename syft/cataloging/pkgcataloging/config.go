package pkgcataloging

import (
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

// Config 结构体定义了包目录编制器的配置参数。
// 每个字段对应一种类型的包 (例如 Binary 用于二进制可执行文件，Golang 用于 Golang 包)。
// 每个字段的类型都来自导入的子包，并提供了针对该类型包的特定配置选项。
type Config struct {
	Binary      binary.ClassifierCatalogerConfig  `yaml:"binary" json:"binary" mapstructure:"binary"`
	Golang      golang.CatalogerConfig            `yaml:"golang" json:"golang" mapstructure:"golang"`
	JavaArchive java.ArchiveCatalogerConfig       `yaml:"java-archive" json:"java-archive" mapstructure:"java-archive"`
	JavaScript  javascript.CatalogerConfig        `yaml:"javascript" json:"javascript" mapstructure:"javascript"`
	LinuxKernel kernel.LinuxKernelCatalogerConfig `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python      python.CatalogerConfig            `yaml:"python" json:"python" mapstructure:"python"`
}

// DefaultConfig() 函数返回一个默认的 Config 配置。
func DefaultConfig() Config {
	return Config{
		Binary:      binary.DefaultClassifierCatalogerConfig(),
		Golang:      golang.DefaultCatalogerConfig(),
		LinuxKernel: kernel.DefaultLinuxKernelCatalogerConfig(),
		Python:      python.DefaultCatalogerConfig(),
		JavaArchive: java.DefaultArchiveCatalogerConfig(),
	}
}

// 其他函数用于修改 Config 配置的特定部分：
// With...Config(cfg ...) 系列函数，分别用于更新不同类型包的配置
// (例如 WithBinaryConfig(cfg binary.ClassifierCatalogerConfig))。
func (c Config) WithBinaryConfig(cfg binary.ClassifierCatalogerConfig) Config {
	c.Binary = cfg
	return c
}

func (c Config) WithGolangConfig(cfg golang.CatalogerConfig) Config {
	c.Golang = cfg
	return c
}

func (c Config) WithJavascriptConfig(cfg javascript.CatalogerConfig) Config {
	c.JavaScript = cfg
	return c
}

func (c Config) WithLinuxKernelConfig(cfg kernel.LinuxKernelCatalogerConfig) Config {
	c.LinuxKernel = cfg
	return c
}

func (c Config) WithPythonConfig(cfg python.CatalogerConfig) Config {
	c.Python = cfg
	return c
}

func (c Config) WithJavaArchiveConfig(cfg java.ArchiveCatalogerConfig) Config {
	c.JavaArchive = cfg
	return c
}
