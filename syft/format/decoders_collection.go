package format

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/sbom"
)

// 声明了一个空接口类型的变量 _ sbom.FormatDecoder
// 这是一种称为接口匿名的技术，用于确保 DecoderCollection 类型隐式地实现了 sbom.FormatDecoder 接口。
// sbom.FormatDecoder 接口可能定义了用于解码 SBOM 数据的方法（例如 Decode 和 Identify）。
var _ sbom.FormatDecoder = (*DecoderCollection)(nil)

// 该类型表示一个解码器集合，它包含了一个切片 decoders，用于存储各种 SBOM 格式解码器。
type DecoderCollection struct {
	decoders []sbom.FormatDecoder
}

// 此函数用于创建一个新的 DecoderCollection 实例。它接受零个或多个 sbom.FormatDecoder 接口类型的参数，并将它们存储在创建的 DecoderCollection 实例的 decoders 切片中。
func NewDecoderCollection(decoders ...sbom.FormatDecoder) sbom.FormatDecoder {
	return &DecoderCollection{
		decoders: decoders,
	}
}

// 此函数尝试解码给定读取器 (reader) 中的 SBOM 数据。
// 首先检查 reader 是否为空，如果不为空，则遍历 decoders 切片中的每个解码器。
// 对于每个解码器，它调用 d.Identify(reader) 方法尝试识别 SBOM 格式并获取格式标识符 (id) 和版本信息 (version)。
// 如果解码器无法识别格式，则会跳过该解码器并继续下一个。
// 如果找到可以识别的格式，并且解码器同时提供了格式标识符和版本信息，则会直接调用该解码器的 d.Decode(reader) 方法进行解码并返回结果。
// 如果遍历完所有解码器后都没有找到可以识别的格式，但识别到了格式标识符，则会返回错误信息，表明找到格式但版本不受支持。
// 如果遍历完所有解码器后都无法识别格式，则会返回错误信息，表明无法识别 SBOM 格式。
// Decode takes a set of bytes and attempts to decode it into an SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Decode(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	if reader == nil {
		return nil, "", "", fmt.Errorf("no SBOM bytes provided")
	}
	var bestID sbom.FormatID
	for _, d := range c.decoders {
		id, version := d.Identify(reader)
		if id == "" || version == "" {
			if id != "" {
				bestID = id
			}
			continue
		}

		return d.Decode(reader)
	}

	if bestID != "" {
		return nil, bestID, "", fmt.Errorf("sbom format found to be %q but the version is not supported", bestID)
	}

	return nil, "", "", fmt.Errorf("sbom format not recognized")
}

// 此函数尝试识别给定读取器 (reader) 中的 SBOM 数据的格式。
// 类似于 Decode 函数，它会遍历 decoders 切片中的每个解码器，并调用它们的 Identify 方法尝试识别格式。
// 如果找到可以识别的格式，并且解码器同时提供了格式标识符 (id) 和版本信息 (version)，则会直接返回这两个值。
// 如果遍历完所有解码器后都无法识别格式，则会返回空字符串。
// Identify takes a set of bytes and attempts to identify the format of the SBOM relative to the decoders in the collection.
func (c *DecoderCollection) Identify(reader io.Reader) (sbom.FormatID, string) {
	if reader == nil {
		return "", ""
	}
	for _, d := range c.decoders {
		id, version := d.Identify(reader)
		if id != "" && version != "" {
			return id, version
		}
	}
	return "", ""
}
