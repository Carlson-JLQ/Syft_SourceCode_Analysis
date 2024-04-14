package format

import (
	"io"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
)

// 这是一个静态变量，用于存储一个实现了 sbom.FormatDecoder 接口的对象。
var staticDecoders sbom.FormatDecoder

// init 函数会在程序启动时自动执行，它将通过调用 NewDecoderCollection 函数并传入 Decoders 函数返回的解码器集合来初始化 staticDecoders 变量。
func init() {
	staticDecoders = NewDecoderCollection(Decoders()...)
}

// Decoders 函数：此函数返回一个切片，其中包含了各种 SBOM 格式解码器的实例。
// syftjson.NewFormatDecoder()：可能用于解码 Syft JSON 格式的 SBOM。
// cyclonedxxml.NewFormatDecoder() 和 cyclonedxjson.NewFormatDecoder()：可能分别用于解码 CycloneDX XML 和 JSON 格式的 SBOM。
// spdxtagvalue.NewFormatDecoder() 和 spdxjson.NewFormatDecoder()：可能分别用于解码 SPDX tag-value 和 JSON 格式的 SBOM。
func Decoders() []sbom.FormatDecoder {
	return []sbom.FormatDecoder{
		syftjson.NewFormatDecoder(),
		cyclonedxxml.NewFormatDecoder(),
		cyclonedxjson.NewFormatDecoder(),
		spdxtagvalue.NewFormatDecoder(),
		spdxjson.NewFormatDecoder(),
	}
}

// 此函数尝试识别给定读取器 (reader) 中的 SBOM 数据的格式。它将数据传递给内部的 staticDecoders 对象，并调用其 Identify 方法进行格式识别。该方法会返回格式标识符 (sbom.FormatID) 和版本信息 (string)（可选）。
// Identify takes a set of bytes and attempts to identify the format of the SBOM.
func Identify(reader io.Reader) (sbom.FormatID, string) {
	return staticDecoders.Identify(reader)
}

// 此函数尝试解码给定读取器 (reader) 中的 SBOM 数据。它将数据传递给内部的 staticDecoders 对象，并调用其 Decode 方法进行解码。该方法会尝试将数据解码成 sbom.SBOM 对象，并返回解码后的 SBOM 对象、格式标识符 (sbom.FormatID)、版本信息 (string)（可选），以及解码过程中遇到的任何错误。
// Decode takes a set of bytes and attempts to decode it into an SBOM.
func Decode(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	return staticDecoders.Decode(reader)
}
