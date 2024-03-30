package file

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// directoryEndLen, readByf, directoryEnd, and findSignatureInBlock were copied from the golang stdlib, specifically:
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/struct.go
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/reader.go
// findArchiveStartOffset is derived from the same stdlib utils, specifically the readDirectoryEnd function.

// directoryEndLen、readByf、directoryEnd 和 findSignatureInBlock 函数从 golang 标准库复制而来，具体来自：
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/struct.go
// - https://github.com/golang/go/blob/go1.16.4/src/archive/zip/reader.go
// findArchiveStartOffset 函数来自相同的标准库工具，特别是 readDirectoryEnd 函数。

// directoryEndLen: 目录结束签名的长度（以字节为单位）。
// directory64LocLen: ZIP64 定位器签名的长度（以字节为单位）。
// directory64EndLen: ZIP64 目录结束签名的长度（以字节为单位）。
// directory64LocSignature: ZIP64 定位器的签名值。
// directory64EndSignature: ZIP64 目录结束的签名值。
const (
	directoryEndLen         = 22
	directory64LocLen       = 20
	directory64EndLen       = 56
	directory64LocSignature = 0x07064b50
	directory64EndSignature = 0x06064b50
)

// ZipReadCloser is a drop-in replacement for zip.ReadCloser (from zip.OpenReader) that additionally considers zips
// that have bytes prefixed to the front of the archive (common with self-extracting jars).
// 此结构封装了一个 zip.Reader 并提供了一个 Closer 接口。
type ZipReadCloser struct {
	*zip.Reader
	io.Closer
}

// OpenZip provides a ZipReadCloser for the given filepath.
// 此函数打开指定路径处的 ZIP 文件。
// 首先，它通过调用 findArchiveStartOffset 检查任何附加数据。
// 然后，它将指针移到实际 ZIP 数据的开头，并使用 zip.NewReader 创建一个读取器。
// 最后，它返回一个 ZipReadCloser 结构。
func OpenZip(filepath string) (*ZipReadCloser, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	//// Stat 函数返回描述文件 file 的 FileInfo 结构体。
	//// 如果发生错误，它将是 *PathError 类型。
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	// some archives may have bytes prepended to the front of the archive, such as with self executing JARs. We first
	// need to find the start of the archive and keep track of this offset.
	//一些存档文件可能在其开头附加了一些字节，例如自解压 JAR 文件。我们首先需要找到存档的开头并跟踪此偏移量
	//findArchiveStartOffset用于查找压缩文件的实际数据开始位置
	offset, err := findArchiveStartOffset(f, fi.Size())
	if err != nil {
		return nil, fmt.Errorf("cannot find beginning of zip archive=%q : %w", filepath, err)
	}
	//Seek 方法用于设置文件指针的位置。
	//offset 表示要设置的新位置，它是一个相对于文件开头或结尾的字节偏移量。
	//whence 参数的三个可能值及其含义
	//0: 将 offset 视为相对于文件开头的偏移量。
	//1: 将 offset 视为相对于当前文件指针位置的偏移量。
	//2: 将 offset 视为相对于文件结尾的偏移量。
	//返回新的文件指针位置
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("unable to seek to beginning of archive: %w", err)
	}

	size := fi.Size() - int64(offset)

	r, err := zip.NewReader(io.NewSectionReader(f, int64(offset), size), size)
	if err != nil {
		return nil, fmt.Errorf("unable to open ZipReadCloser @ %q: %w", filepath, err)
	}

	return &ZipReadCloser{
		Reader: r,
		Closer: f,
	}, nil
}

// 这是一种自定义类型，它封装了一个字节切片并提供用于读取小端字节序 uint16、uint32 和 uint64 值的方法。
type readBuf []byte

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.LittleEndian.Uint64(*b)
	*b = (*b)[8:]
	return v
}

// 此结构表示 ZIP 存档中的目录结束头。
// 它包含用于未使用数据和与中央目录相关的偏移量的字段。
type directoryEnd struct {
	diskNbr            uint32 // unused
	dirDiskNbr         uint32 // unused
	dirRecordsThisDisk uint64 // unused
	directoryRecords   uint64
	directorySize      uint64
	directoryOffset    uint64 // relative to file
}

// note: this is derived from readDirectoryEnd within the archive/zip package
// 此函数在文件的末尾搜索 ZIP 目录结束签名。
// 它读取最后的 1KB 然后读取最后的 65KB 来查找签名。
// 如果找到，它会解析目录结束头以计算 ZIP 数据的实际起始位置。
// 它还通过搜索和读取 ZIP64 定位器和结束结构来处理 ZIP64 存档。
// findArchiveStartOffset用于查找压缩文件的实际数据开始位置
// startOfArchive: 压缩数据开始的偏移量（以字节为单位）,也就是压缩文件的实际数据开始位置
//
//nolint:gocognit
func findArchiveStartOffset(r io.ReaderAt, size int64) (startOfArchive uint64, err error) {
	// look for directoryEndSignature in the last 1k, then in the last 65k
	var buf []byte
	var directoryEndOffset int64
	//查找目录结束标志:
	//
	//在文件的最后 1KB 和最后 65KB 中查找目录结束标志（通常为 PK\05\06）。
	//循环两次：第一次读取最后 1KB，第二次读取最后 65KB。
	//使用 findSignatureInBlock 函数在读取的块中查找目录结束标志。
	//如果找到标志，则记录标志在文件中的偏移量并退出循环。
	//如果在两次循环中都没有找到标志，则返回错误（zip.ErrFormat）。
	for i, bLen := range []int64{1024, 65 * 1024} {
		if bLen > size {
			bLen = size
		}
		buf = make([]byte, int(bLen))
		//ReadAt从偏移size-bLen处取得buf个字节返回
		if _, err := r.ReadAt(buf, size-bLen); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if p := findSignatureInBlock(buf); p >= 0 {
			buf = buf[p:]
			directoryEndOffset = size - bLen + int64(p)
			break
		}
		if i == 1 || bLen == size {
			return 0, zip.ErrFormat
		}
	}

	if buf == nil {
		// we were unable to find the directoryEndSignature block
		return 0, zip.ErrFormat
	}

	// read header into struct
	b := readBuf(buf[4:]) // skip signature
	d := &directoryEnd{
		diskNbr:            uint32(b.uint16()),
		dirDiskNbr:         uint32(b.uint16()),
		dirRecordsThisDisk: uint64(b.uint16()),
		directoryRecords:   uint64(b.uint16()),
		directorySize:      uint64(b.uint32()),
		directoryOffset:    uint64(b.uint32()),
	}
	// Calculate where the zip data actually begins

	// These values mean that the file can be a zip64 file
	if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff {
		p, err := findDirectory64End(r, directoryEndOffset)
		if err == nil && p >= 0 {
			directoryEndOffset = p
			err = readDirectory64End(r, p, d)
		}
		if err != nil {
			return 0, err
		}
	}
	startOfArchive = uint64(directoryEndOffset) - d.directorySize - d.directoryOffset

	// Make sure directoryOffset points to somewhere in our file.
	if o := int64(d.directoryOffset); o < 0 || o >= size {
		return 0, zip.ErrFormat
	}
	return startOfArchive, nil
}

// findDirectory64End tries to read the zip64 locator just before the
// directory end and returns the offset of the zip64 directory end if
// found.
// 此函数在目录结束之前搜索 ZIP64 定位器签名。
// 它读取定位器数据以获取 ZIP64 目录结束的偏移量。
func findDirectory64End(r io.ReaderAt, directoryEndOffset int64) (int64, error) {
	locOffset := directoryEndOffset - directory64LocLen
	if locOffset < 0 {
		return -1, nil // no need to look for a header outside the file
	}
	buf := make([]byte, directory64LocLen)
	if _, err := r.ReadAt(buf, locOffset); err != nil {
		return -1, err
	}
	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64LocSignature {
		return -1, nil
	}
	if b.uint32() != 0 { // number of the disk with the start of the zip64 end of central directory
		return -1, nil // the file is not a valid zip64-file
	}
	p := b.uint64()      // relative offset of the zip64 end of central directory record
	if b.uint32() != 1 { // total number of disks
		return -1, nil // the file is not a valid zip64-file
	}
	return int64(p), nil
}

// readDirectory64End reads the zip64 directory end and updates the
// directory end with the zip64 directory end values.
// 此函数读取 ZIP64 目录结束结构并使用 ZIP64 值更新提供的 directoryEnd 结构。
func readDirectory64End(r io.ReaderAt, offset int64, d *directoryEnd) (err error) {
	buf := make([]byte, directory64EndLen)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}

	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64EndSignature {
		return errors.New("could not read directory64End")
	}

	b = b[12:]                        // skip dir size, version and version needed (uint64 + 2x uint16)
	d.diskNbr = b.uint32()            // number of this disk
	d.dirDiskNbr = b.uint32()         // number of the disk with the start of the central directory
	d.dirRecordsThisDisk = b.uint64() // total number of entries in the central directory on this disk
	d.directoryRecords = b.uint64()   // total number of entries in the central directory
	d.directorySize = b.uint64()      // size of the central directory
	d.directoryOffset = b.uint64()    // offset of start of central directory with respect to the starting disk number

	return nil
}

// 此函数在字节切片中搜索 ZIP 目录结束签名。
// 它从切片的末尾向后迭代以查找签名模式。
func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		// defined from directoryEndSignature
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			// n is length of comment
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i <= len(b) {
				return i
			}
		}
	}
	return -1
}
