package filecataloging

//用于配置文件目录编制器
import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/executable"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
)

// Config 结构体定义了文件目录编制器的配置参数
type Config struct {
	// 指定要编制目录的文件选择器 (类型为 file.Selection)。
	Selection file.Selection `yaml:"selection" json:"selection" mapstructure:"selection"`
	//指定用于计算文件哈希的算法列表 (类型为 []crypto.Hash)
	Hashers []crypto.Hash `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
	//配置文件内容分析 (类型为 filecontent.Config)。
	Content filecontent.Config `yaml:"content" json:"content" mapstructure:"content"`
	//配置可执行文件分析 (类型为 executable.Config)。
	Executable executable.Config `yaml:"executable" json:"executable" mapstructure:"executable"`
}

// configMarshaledForm 结构体用于 JSON 编码时的中间格式。
// 它包含了 Selection 和将哈希算法转换为字符串的 Hashers 列表
type configMarshaledForm struct {
	Selection file.Selection     `yaml:"selection" json:"selection" mapstructure:"selection"`
	Hashers   []string           `yaml:"hashers" json:"hashers" mapstructure:"hashers"`
	Content   filecontent.Config `yaml:"content" json:"content" mapstructure:"content"`
}

// DefaultConfig() 函数返回一个默认的 Config 配置
func DefaultConfig() Config {

	hashers, err := intFile.Hashers("sha256")
	if err != nil {
		log.WithFields("error", err).Warn("unable to create file hashers")
	}
	return Config{
		Selection:  file.FilesOwnedByPackageSelection,
		Hashers:    hashers,
		Content:    filecontent.DefaultConfig(),
		Executable: executable.DefaultConfig(),
	}
}

// (cfg Config).MarshalJSON() 函数将 Config 配置转换为 JSON 格式的字节数组。
// 它首先创建一个 configMarshaledForm 结构体，并填充相应的数据。
// 然后使用 json.Marshal() 函数将其转换为 JSON 格式的字节数组。
func (cfg Config) MarshalJSON() ([]byte, error) {
	marshaled := configMarshaledForm{
		Selection: cfg.Selection,
		Hashers:   hashersToString(cfg.Hashers),
	}
	return json.Marshal(marshaled)
}

// hashersToString(hashers []crypto.Hash) 函数将哈希算法列表转换为字符串列表。
// 它遍历哈希算法列表，并将其转换为小写的字符串。
func hashersToString(hashers []crypto.Hash) []string {
	var result []string
	for _, h := range hashers {
		result = append(result, strings.ToLower(h.String()))
	}
	return result
}

// (cfg *Config).UnmarshalJSON(data []byte) 函数将 JSON 格式的字节数组转换为 Config 配置。
// 它首先将 JSON 数据反序列化到 configMarshaledForm 结构体。
// 然后，它解析哈希算法字符串并转换为实际的 crypto.Hash 对象。
// 最后，它更新 Config 配置中的各个字段。
func (cfg *Config) UnmarshalJSON(data []byte) error {
	var marshaled configMarshaledForm
	if err := json.Unmarshal(data, &marshaled); err != nil {
		return err
	}

	hashers, err := intFile.Hashers(marshaled.Hashers...)
	if err != nil {
		return fmt.Errorf("unable to parse configured hashers: %w", err)
	}
	cfg.Selection = marshaled.Selection
	cfg.Hashers = hashers
	return nil
}

// 其他函数用于修改 Config 配置的特定部分：
// WithSelection(selection file.Selection): 更新 Selection 配置。
// WithHashers(hashers ...crypto.Hash): 更新 Hashers 配置。
// WithContentConfig(content filecontent.Config): 更新 Content 配置
func (cfg Config) WithSelection(selection file.Selection) Config {
	cfg.Selection = selection
	return cfg
}

func (cfg Config) WithHashers(hashers ...crypto.Hash) Config {
	cfg.Hashers = intFile.NormalizeHashes(hashers)
	return cfg
}

func (cfg Config) WithContentConfig(content filecontent.Config) Config {
	cfg.Content = content
	return cfg
}
