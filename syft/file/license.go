package file

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/license"
)

// 该代码定义了 License 结构体，用于表示软件许可证信息。

// License:
//
// Value: 字符串，表示许可证的文本内容。
// SPDXExpression: 字符串，SPDX 许可证表达式 (如果解析成功)。
// Type: license.Type 类型，表示许可证的类型 (例如，MIT、Apache-2.0 等)。
// LicenseEvidence (可选)：LicenseEvidence 类型指针，指向许可证识别的证据信息。
type License struct {
	Value           string
	SPDXExpression  string
	Type            license.Type
	LicenseEvidence *LicenseEvidence // evidence from license classifier
}

// LicenseEvidence:
//
// Confidence: 整数，表示许可证识别置信度 (范围未知)。
// Offset: 整数，表示许可证文本在文件中出现的偏移量 (可能用于定位许可证文本)。
// Extent: 整数，表示许可证文本在文件中的长度 (可能用于定位许可证文本)。
type LicenseEvidence struct {
	Confidence int
	Offset     int
	Extent     int
}

// NewLicense: 创建一个新的 License 实例。
// 它会尝试解析提供的许可证文本 (value) 成 SPDX 许可证表达式。
// 如果解析失败，会记录日志信息，但仍然会创建一个 License 实例，只是 SPDXExpression 和 Type 可能不准确。
func NewLicense(value string) License {
	spdxExpression, err := license.ParseExpression(value)
	if err != nil {
		log.Trace("unable to parse license expression: %s, %w", value, err)
	}

	return License{
		Value:          value,
		SPDXExpression: spdxExpression,
		Type:           license.Concluded,
	}
}
