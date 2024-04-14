package spdxjson

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	spdxJson "github.com/spdx/tools-golang/json"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/sbom"
)

// 这行代码的作用是进行类型断言。它断言 decoder 类型实现了 sbom.FormatDecoder 接口。这是一种常用的方式来确保实现了接口的方法。
var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
}

// 用于创建一个新的 SPDX JSON 格式解码器实例。
func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

// 该函数用于从给定的可读流 (io.Reader) 中读取 SPDX JSON 数据，并将其解码成 sbom.SBOM 对象。
// 首先确保流可以定位 (以便重复读取数据)。
// 然后调用 Identify 函数识别 SPDX JSON 文档的格式和版本信息。
// 如果识别到格式为 SPDX JSON，则重新定位流到开头并使用 spdx/tools-golang/json 库读取文档内容。
// 最后，将读取到的 SPDX JSON 文档转换为 syft.SBOM 对象并返回。
func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", err
	}
	//这段注释解释了为什么解码器需要在解码之前识别 SPDX JSON 文档的版本。这是因为使用的第三方库 (spdx/tools-golang/json)总是返回最新版本的文档，如果不提前识别版本，就无法解码成对应版本的具体对象。
	// since spdx lib will always return the latest version of the document, we need to identify the version
	// first and then decode into the appropriate document object. Otherwise if we get the version info from the
	// decoded object we will always get the latest version (instead of the version we decoded from).
	id, version := d.Identify(reader)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a spdx json document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported spdx json document version")
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", fmt.Errorf("unable to seek to start of SPDX JSON SBOM: %+v", err)
	}

	doc, err := spdxJson.Read(reader)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode spdx json: %w", err)
	}

	s, err := spdxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}
	return s, id, version, nil
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return "", ""
	}

	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		log.Debugf("unable to seek to start of SPDX JSON SBOM: %+v", err)
		return "", ""
	}

	// Example JSON document
	// {
	// "spdxVersion": "SPDX-2.3",
	// ...
	type Document struct {
		SPDXVersion string `json:"spdxVersion"`
	}

	dec := json.NewDecoder(reader)

	var doc Document
	if err = dec.Decode(&doc); err != nil {
		//这段注释解释了当无法解码文档头部 (可能不是有效的 JSON 格式或不支持的版本) 时，解码器会跳过该文件。
		// maybe not json? maybe not valid? doesn't matter, we won't process it.
		return "", ""
	}

	id, version := getFormatInfo(doc.SPDXVersion)
	if version == "" || id != ID {
		// not a spdx json document that we support
		return "", ""
	}

	return id, version
}

// 输入SPDX-2.3，返回SPDX，2.3
func getFormatInfo(spdxVersion string) (sbom.FormatID, string) {
	// example input: SPDX-2.3
	if !strings.HasPrefix(strings.ToLower(spdxVersion), "spdx-") {
		return "", ""
	}
	fields := strings.Split(spdxVersion, "-")
	if len(fields) != 2 {
		return ID, ""
	}

	return ID, fields[1]
}
