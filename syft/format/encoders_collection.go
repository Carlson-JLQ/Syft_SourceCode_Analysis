package format

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

// 该类型表示一个 SBOM 编码器集合，它包含了一个切片 encoders 来存储各种格式的 SBOM 编码器
type EncoderCollection struct {
	encoders []sbom.FormatEncoder
}

// 此函数用于创建一个新的 EncoderCollection 实例。它接受零个或多个 sbom.FormatEncoder 接口类型的参数，并将它们存储在创建的 EncoderCollection 实例的 encoders 切片中。
func NewEncoderCollection(encoders ...sbom.FormatEncoder) *EncoderCollection {
	return &EncoderCollection{
		encoders: encoders,
	}
}

// IDs() []sbom.FormatID：此函数返回集合中所有支持的 SBOM 格式标识符 (sbom.FormatID) 列表。
// 它首先使用 strset.New() 创建一个字符串集合 (idSet)。
// 然后遍历 encoders 切片中的每个编码器，并将其格式标识符添加到集合中。
// 最后，它将集合转换为排序后的字符串列表 (idList)，并将其转换为 sbom.FormatID 列表返回。
// IDs returns all format IDs represented in the collection.
func (e EncoderCollection) IDs() []sbom.FormatID {
	idSet := strset.New()
	for _, f := range e.encoders {
		idSet.Add(string(f.ID()))
	}

	idList := idSet.List()
	sort.Strings(idList)

	var ids []sbom.FormatID
	for _, id := range idList {
		ids = append(ids, sbom.FormatID(id))
	}

	return ids
}

// NameVersions() []string：此函数返回集合中所有支持的 SBOM 格式的名称和版本信息列表 (格式为 "name@version")。
// 它首先使用 strset.New() 创建一个字符串集合 (set)。
// 然后遍历 encoders 切片中的每个编码器，并根据其版本信息将格式添加到集合中。
// 如果版本为 sbom.AnyVersion (表示支持所有版本)，则只添加格式名称。
// 否则，将格式名称和版本信息拼接成 "name@version" 格式并添加到集合中。
// 最后，它将集合转换为排序后的字符串列表并返回。
// NameVersions returns all formats that are supported by the collection as a list of "name@version" strings.
func (e EncoderCollection) NameVersions() []string {
	set := strset.New()
	for _, f := range e.encoders {
		if f.Version() == sbom.AnyVersion {
			set.Add(string(f.ID()))
		} else {
			set.Add(fmt.Sprintf("%s@%s", f.ID(), f.Version()))
		}
	}

	list := set.List()
	sort.Strings(list)

	return list
}

// Aliases() []string：此函数返回集合中所有支持的 SBOM 格式的别名列表。
// 它遍历 encoders 切片中的每个编码器，并将其所有的别名添加到一个 strset.New() 创建的字符串集合 (aliases) 中。
// 最后，将集合转换为排序后的字符串列表并返回。
// Aliases returns all format aliases represented in the collection (where an ID would be "spdx-tag-value" the alias would be "spdx").
func (e EncoderCollection) Aliases() []string {
	aliases := strset.New()
	for _, f := range e.encoders {
		aliases.Add(f.Aliases()...)
	}
	lst := aliases.List()
	sort.Strings(lst)
	return lst
}

// Get(name string, version string) sbom.FormatEncoder：此函数用于根据名称和版本信息获取集合中对应的 SBOM 编码器。
// 它首先对名称进行清理 (小写、去除特殊字符)。
// 然后遍历 encoders 切片中的每个编码器，并检查其名称 (包括别名) 和版本信息是否与给定参数匹配。
// 如果找到匹配的编码器，并且该编码器的版本比之前找到的更高级 (对于支持多版本的格式)，则将其更新为最新的匹配编码器。
// 该函数使用日志记录功能 (log) 来跟踪匹配过程。
// 如果找到匹配的编码器，则返回该编码器，否则返回 nil。
// Get returns the contained encoder for a given format name and version.
func (e EncoderCollection) Get(name string, version string) sbom.FormatEncoder {
	log.WithFields("name", name, "version", version).Trace("looking for matching encoder")

	name = cleanFormatName(name)
	var mostRecentFormat sbom.FormatEncoder

	for _, f := range e.encoders {
		log.WithFields("name", f.ID(), "version", f.Version(), "aliases", f.Aliases()).Trace("considering format")
		names := []string{string(f.ID())}
		names = append(names, f.Aliases()...)
		for _, n := range names {
			if cleanFormatName(n) == name && versionMatches(f.Version(), version) {
				if mostRecentFormat == nil || f.Version() > mostRecentFormat.Version() {
					mostRecentFormat = f
				}
			}
		}
	}

	if mostRecentFormat != nil {
		log.WithFields("name", mostRecentFormat.ID(), "version", mostRecentFormat.Version()).Trace("found matching encoder")
	} else {
		log.WithFields("search-name", name, "search-version", version).Trace("no matching encoder found")
	}

	return mostRecentFormat
}

// GetByString accepts a name@version string, such as:
//   - json
//   - spdx-json@2.1
//   - cdx@1.5
//
// 此函数用于根据格式字符串 (例如 "json" 或 "spdx-json@2.1") 获取对应的 SBOM 编码器。
// 它首先将格式字符串按照 "@" 符号分割成名称和版本两部分。
// 然后调用 Get 函数来根据解析出的名称和版本信息获取对应的编码器。
func (e EncoderCollection) GetByString(s string) sbom.FormatEncoder {
	parts := strings.SplitN(s, "@", 2)
	version := sbom.AnyVersion
	if len(parts) > 1 {
		version = parts[1]
	}
	return e.Get(parts[0], version)
}

// 此函数用于检查给定版本号 (version) 是否与匹配字符串 (match) 匹配。
// 它支持通配符 (*) 和版本范围匹配。
// 该函数使用正则表达式来实现匹配功能。
func versionMatches(version string, match string) bool {
	if version == sbom.AnyVersion || match == sbom.AnyVersion {
		return true
	}

	match = strings.ReplaceAll(match, ".", "\\.")
	match = strings.ReplaceAll(match, "*", ".*")
	match = fmt.Sprintf("^%s(\\..*)*$", match)
	matcher, err := regexp.Compile(match)
	if err != nil {
		return false
	}
	return matcher.MatchString(version)
}

// 此函数用于清理格式名称，将其转换为小写并去除特殊字符。
func cleanFormatName(name string) string {
	r := strings.NewReplacer("-", "", "_", "")
	return strings.ToLower(r.Replace(name))
}

// 此函数用于使用指定的 SBOM 编码器 (f) 将 SBOM 数据 (s) 编码成字节数组。
// 它首先创建一个缓冲区 (buff)。
// 然后调用编码器 f.Encode(&buff, s) 方法将 SBOM 数据编码并写入缓冲区。
// 如果编码过程中遇到错误，则会返回错误信息。
// 最后，将缓冲区中的内容转换为字节数组并返回。
// Encode takes all SBOM elements and a format option and encodes an SBOM document.
func Encode(s sbom.SBOM, f sbom.FormatEncoder) ([]byte, error) {
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}
