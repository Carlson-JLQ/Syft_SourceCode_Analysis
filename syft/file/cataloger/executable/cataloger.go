package executable

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

// 该代码定义了 Cataloger 类型，用于发现和分类系统中的可执行文件。

// MIMETypes: 字符串列表，指定用于识别可执行文件的 MIME 类型。
// Globs: 字符串列表，指定用于进一步过滤可执行文件的匹配规则 (使用 doublestar 库)。
type Config struct {
	MIMETypes []string `json:"mime-types" yaml:"mime-types" mapstructure:"mime-types"`
	Globs     []string `json:"globs" yaml:"globs" mapstructure:"globs"`
}

// Cataloger:
// config: Config 类型配置信息，指定可执行文件的 MIME 类型和匹配规则 (globs)。
// Catalog: 方法，用于扫描系统并识别可执行文件。
type Cataloger struct {
	config Config
}

func DefaultConfig() Config {
	m := mimetype.ExecutableMIMETypeSet.List()
	sort.Strings(m)
	return Config{
		MIMETypes: m,
		Globs:     nil,
	}
}

func NewCataloger(cfg Config) *Cataloger {
	return &Cataloger{
		config: cfg,
	}
}

// Catalog 方法流程:
// 根据配置的 MIME 类型，使用 resolver.FilesByMIMEType 方法查找候选文件列表。
// 使用 filterByGlobs 方法根据配置的 glob 规则进一步过滤文件列表。
// 遍历过滤后的文件列表:
// 使用 resolver.FileContentsByLocation 方法获取文件内容。
// 使用 unionreader.GetUnionReader 方法处理可能存在的压缩文件。
// 调用 processExecutable 方法分析文件格式和安全特性。
// 将分析结果 (可执行文件信息) 存储在字典中，并按文件位置 (Coordinates) 作为键。
// 记录处理过的文件数量并输出相关日志信息。
func (i *Cataloger) Catalog(resolver file.Resolver) (map[file.Coordinates]file.Executable, error) {
	locs, err := resolver.FilesByMIMEType(i.config.MIMETypes...)
	if err != nil {
		return nil, fmt.Errorf("unable to get file locations for binaries: %w", err)
	}

	locs, err = filterByGlobs(locs, i.config.Globs)
	if err != nil {
		return nil, err
	}
	//进度条
	prog := catalogingProgress(int64(len(locs)))

	results := make(map[file.Coordinates]file.Executable)
	for _, loc := range locs {
		prog.AtomicStage.Set(loc.Path())

		reader, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			// TODO: known-unknowns
			log.WithFields("error", err).Warnf("unable to get file contents for %q", loc.RealPath)
			continue
		}

		uReader, err := unionreader.GetUnionReader(reader)
		if err != nil {
			// TODO: known-unknowns
			log.WithFields("error", err).Warnf("unable to get union reader for %q", loc.RealPath)
			continue
		}

		exec, err := processExecutable(loc, uReader)
		if err != nil {
			log.WithFields("error", err).Warnf("unable to process executable %q", loc.RealPath)
		}
		if exec != nil {
			prog.Increment()
			results[loc.Coordinates] = *exec
		}
	}

	log.Debugf("executable cataloger processed %d files", len(results))

	prog.AtomicStage.Set(fmt.Sprintf("%s executables", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, nil
}

// 进度条
func catalogingProgress(locations int64) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Executables",
		},
		ParentID: monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, locations, "")
}

// 该函数用于过滤一组文件位置 (locs)，根据指定的 glob 匹配规则 (globs) 保留符合条件的文件位置。
// 检查 glob 规则是否存在：
//
// 如果 globs 为空，则直接返回原始的文件位置列表 locs，因为没有需要过滤的规则。
// 初始化结果列表：
//
// 创建一个空的切片 filteredLocs，用于存储过滤后的文件位置。
// 遍历所有文件位置：
//
// 对于每个文件位置 loc 进行以下操作：
// 调用 locationMatchesGlob 方法判断该文件位置是否符合任意一个 glob 规则。
// 如果匹配成功 (matches 为 true)，将该文件位置 loc 添加到 filteredLocs 列表中。
// 如果匹配过程中出现错误 (err 不为 nil)，则停止遍历并返回错误。
// 返回过滤结果：
//
// 成功过滤后，返回包含符合 glob 规则的文件位置列表 filteredLocs 和 nil 错误。
func filterByGlobs(locs []file.Location, globs []string) ([]file.Location, error) {
	if len(globs) == 0 {
		return locs, nil
	}
	var filteredLocs []file.Location
	for _, loc := range locs {
		matches, err := locationMatchesGlob(loc, globs)
		if err != nil {
			return nil, err
		}
		if matches {
			filteredLocs = append(filteredLocs, loc)
		}
	}
	return filteredLocs, nil
}

func locationMatchesGlob(loc file.Location, globs []string) (bool, error) {
	for _, glob := range globs {
		for _, path := range []string{loc.RealPath, loc.AccessPath} {
			if path == "" {
				continue
			}
			matches, err := doublestar.Match(glob, path)
			if err != nil {
				return false, fmt.Errorf("unable to match glob %q to path %q: %w", glob, path, err)
			}
			if matches {
				return true, nil
			}
		}
	}
	return false, nil
}

// processExecutable 方法详解:
//
// 尝试读取文件的前 512 个字节，用于判断可执行文件格式.
// 使用 findExecutableFormat 方法根据文件头信息判断格式 (ELF、MachO、PE)。
// 对于确定的可执行文件格式:
// 调用 findSecurityFeatures 方法根据格式解析安全特性 (目前仅支持 ELF)。
// 将解析到的可执行文件信息 (Executable) 返回。
func processExecutable(loc file.Location, reader unionreader.UnionReader) (*file.Executable, error) {
	data := file.Executable{}

	// determine the executable format

	format, err := findExecutableFormat(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to determine executable kind: %w", err)
	}

	if format == "" {
		log.Debugf("unable to determine executable format for %q", loc.RealPath)
		return nil, nil
	}

	data.Format = format

	securityFeatures, err := findSecurityFeatures(format, reader)
	if err != nil {
		log.WithFields("error", err).Tracef("unable to determine security features for %q", loc.RealPath)
		return nil, nil
	}

	data.SecurityFeatures = securityFeatures

	return &data, nil
}

//ELF 代表可执行和可链接格式（Executable and Linkable Format），
//是一种用于可执行文件、目标文件、共享库和核心转储的文件格式。
//它由 Unix System V Release 4 中的应用程序二进制接口 (ABI) 规范首次定义，并很快被不同 Unix 发行版所接受。

// findExecutableFormat 和 findSecurityFeatures 方法 (部分实现):
//
// 这部分代码用于根据文件头信息判断可执行文件格式 (ELF、MachO、PE) 和解析 ELF 格式的安全特性。
// 具体实现细节使用了其他库的功能 (例如 binary、doublestar)，并没有完整列出。
// 代码注释中提到后续会加入对 MachO 和 PE 格式的支持。
func findExecutableFormat(reader unionreader.UnionReader) (file.ExecutableFormat, error) {
	// read the first sector of the file
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		return "", fmt.Errorf("unable to read first sector of file: %w", err)
	}
	if n < 512 {
		return "", fmt.Errorf("unable to read enough bytes to determine executable format")
	}

	switch {
	case isMacho(buf):
		return file.MachO, nil
	case isPE(buf):
		return file.PE, nil
	case isELF(buf):
		return file.ELF, nil
	}

	return "", nil
}

func isMacho(by []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	if classOrMachOFat(by) && by[7] < 20 {
		return true
	}

	if len(by) < 4 {
		return false
	}

	be := binary.BigEndian.Uint32(by)
	le := binary.LittleEndian.Uint32(by)

	return be == macho.Magic32 ||
		le == macho.Magic32 ||
		be == macho.Magic64 ||
		le == macho.Magic64
}

// Java bytecode and Mach-O binaries share the same magic number.
// More info here https://github.com/threatstack/libmagic/blob/master/magic/Magdir/cafebabe
func classOrMachOFat(in []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	// There should be at least 8 bytes for both of them because the only way to
	// quickly distinguish them is by comparing byte at position 7
	if len(in) < 8 {
		return false
	}

	return bytes.HasPrefix(in, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

func isPE(by []byte) bool {
	return bytes.HasPrefix(by, []byte("MZ"))
}

func isELF(by []byte) bool {
	return bytes.HasPrefix(by, []byte(elf.ELFMAG))
}

func findSecurityFeatures(format file.ExecutableFormat, reader unionreader.UnionReader) (*file.ELFSecurityFeatures, error) {
	// TODO: add support for PE and MachO
	switch format { //nolint: gocritic
	case file.ELF:
		return findELFSecurityFeatures(reader) //nolint: gocritic
	case file.PE:
		// return findPESecurityFeatures(reader)
		return nil, nil
	case file.MachO:
		// return findMachOSecurityFeatures(reader)
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported executable format: %q", format)
}
