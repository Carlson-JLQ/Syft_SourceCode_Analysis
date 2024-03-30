package artifact

//artifact 文件夹通常用于存储与软件构建和部署相关的文件
import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"
)

// ID represents a unique value for each package added to a package catalog.
// 每个添加到包目录中的包的 ID 代表一个唯一值
type ID string

type Identifiable interface {
	ID() ID
}

// IDByHash() 函数根据对象的哈希值生成一个 ID。
// 该函数使用 hashstructure 包计算对象的哈希值。
// 然后，将哈希值格式化为 16 进制字符串并返回
func IDByHash(obj interface{}) (ID, error) {
	f, err := hashstructure.Hash(obj, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", fmt.Errorf("could not build ID for object=%+v: %w", obj, err)
	}

	return ID(fmt.Sprintf("%016x", f)), nil
}
