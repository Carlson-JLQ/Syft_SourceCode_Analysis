package file

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

// 该代码定义了 Coordinates 结构体，用于表示文件在来源对象 (例如，镜像、目录) 中的位置信息
// Coordinates contains the minimal information needed to describe how to find a file within any possible source object (e.g. image and directory sources)
type Coordinates struct {
	//字符串，表示文件的真实路径 (绝对路径或相对于来源对象的路径)。 所有祖先目录都没有硬链接或符号链接。
	RealPath string `json:"path" cyclonedx:"path"` // The path where all path ancestors have no hardlinks / symlinks
	//字符串 (可选)，表示文件系统标识。 对于容器镜像，它是层哈希值。 对于目录或根文件系统，则为空。
	FileSystemID string `json:"layerID,omitempty" cyclonedx:"layerID"` // An ID representing the filesystem. For container images, this is a layer digest. For directories or a root filesystem, this is blank.
}

// 计算 Coordinates 实例的唯一标识符 (artifact.ID)。 该标识符基于文件的真实路径和文件系统标识进行哈希计算。
func (c Coordinates) ID() artifact.ID {
	//哈希计算
	f, err := artifact.IDByHash(c)
	if err != nil {
		// TODO: what to do in this case?
		log.Warnf("unable to get fingerprint of location coordinate=%+v: %+v", c, err)
		return ""
	}

	return f
}

func (c Coordinates) String() string {
	str := fmt.Sprintf("RealPath=%q", c.RealPath)

	if c.FileSystemID != "" {
		str += fmt.Sprintf(" Layer=%q", c.FileSystemID)
	}
	return fmt.Sprintf("Location<%s>", str)
}
