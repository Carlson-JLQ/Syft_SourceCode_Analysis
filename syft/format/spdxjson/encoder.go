package spdxjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/sbom"
)

const ID = spdxutil.JSONFormatID

// 返回该编码器支持的 SPDX JSON 文档版本列表 (字符串数组)。
func SupportedVersions() []string {
	return spdxutil.SupportedVersions(ID)
}

// 用于配置 SPDX JSON 编码器，包含版本 (Version) 和格式化 (Pretty) 选项。
type EncoderConfig struct {
	Version string
	Pretty  bool // don't include spaces and newlines; same as jq -c
}

type encoder struct {
	cfg EncoderConfig
}

// 根据给定的配置 (EncoderConfig) 创建一个新的 SPDX JSON 编码器实例。
func NewFormatEncoderWithConfig(cfg EncoderConfig) (sbom.FormatEncoder, error) {
	return encoder{
		cfg: cfg,
	}, nil
}

func DefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		Version: spdxutil.DefaultVersion,
		Pretty:  false,
	}
}

// 返回编码器的格式标识符 (sbom.FormatID)，为 spdxutil.JSONFormatID。
func (e encoder) ID() sbom.FormatID {
	return ID
}

// 返回编码器的别名列表 (空列表)。
func (e encoder) Aliases() []string {
	return []string{}
}

// 返回编码器配置的版本信息。
func (e encoder) Version() string {
	return e.cfg.Version
}

// 将 SBOM 数据 (s) 编码成 SPDX JSON 格式并写入指定的输出流 (writer)。
// 首先将 SBOM 数据转换为内部使用的 SPDX 文档模型 (latestDoc)。
// 然后根据编码器配置的版本 (Version)，使用相应的 spdx/tools-golang/spdx/v2/vX.X 库将内部文档模型转换为特定的 SPDX JSON 文档格式 (encodeDoc)。
// 最后，使用 encoding/json 库将编码后的 SPDX JSON 文档写入输出流。
func (e encoder) Encode(writer io.Writer, s sbom.SBOM) error {
	latestDoc := spdxhelpers.ToFormatModel(s)
	if latestDoc == nil {
		return fmt.Errorf("unable to convert SBOM to SPDX document")
	}

	var err error
	var encodeDoc any
	switch e.cfg.Version {
	case "2.1":
		doc := v2_1.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc
	case "2.2":
		doc := v2_2.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc

	case "2.3":
		doc := v2_3.Document{}
		err = convert.Document(latestDoc, &doc)
		encodeDoc = doc
	default:
		return fmt.Errorf("unsupported SPDX version %q", e.cfg.Version)
	}

	if err != nil {
		return fmt.Errorf("unable to convert SBOM to SPDX document: %w", err)
	}

	enc := json.NewEncoder(writer)

	enc.SetEscapeHTML(false)

	if e.cfg.Pretty {
		enc.SetIndent("", " ")
	}

	return enc.Encode(encodeDoc)
}
