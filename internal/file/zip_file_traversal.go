package file

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/internal/log"
)

const (
	// represents the order of bytes
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)

// 这是一个自定义的错误类型，用于检测提取 ZIP 文件时可能发生路径穿越漏洞的情况。
type errZipSlipDetected struct {
	Prefix   string
	JoinArgs []string
}

func (e *errZipSlipDetected) Error() string {
	return fmt.Sprintf("paths are not allowed to resolve outside of the root prefix (%q). Destination: %q", e.Prefix, e.JoinArgs)
}

// zipTraversalRequest 是一个使用字符串作为键的 map 类型，用于表示要遍历的 ZIP 存档中的文件路径集合。
// 其中的键是字符串类型，值为空的结构体struct{}。这里用空结构体的原因是为了模拟一个“集合”或“存在性映射”，不需要实际的值，只需要键的存在性来表示某个路径是否被包括在集合中。
type zipTraversalRequest map[string]struct{}

// newZipTraverseRequest 函数根据提供的路径字符串创建 zipTraversalRequest 对象。
func newZipTraverseRequest(paths ...string) zipTraversalRequest {
	results := make(zipTraversalRequest)
	for _, p := range paths {
		results[p] = struct{}{}
	}
	return results
}

// TraverseFilesInZip enumerates all paths stored within a zip archive using the visitor pattern.
// TraverseFilesInZip 函数用于遍历 ZIP 存档中的文件。
// 它使用提供的访问者函数 (visitor) 处理每个文件。
// 如果未提供要遍历的路径，则会遍历存档中的所有文件。
// 否则，它将只遍历与提供的路径匹配的文件。
func TraverseFilesInZip(archivePath string, visitor func(*zip.File) error, paths ...string) error {
	request := newZipTraverseRequest(paths...)
	//OpenZip将指针移到实际 ZIP 数据的开头，并使用 zip.NewReader 创建一个读取器。
	zipReader, err := OpenZip(archivePath)
	if err != nil {
		return fmt.Errorf("unable to open zip archive (%s): %w", archivePath, err)
	}
	defer func() {
		err = zipReader.Close()
		if err != nil {
			log.Errorf("unable to close zip archive (%s): %+v", archivePath, err)
		}
	}()

	for _, file := range zipReader.Reader.File {
		// if no paths are given then assume that all files should be traversed
		if len(paths) > 0 {
			if _, ok := request[file.Name]; !ok {
				// this file path is not of interest
				continue
			}
		}

		if err = visitor(file); err != nil {
			return err
		}
	}
	return nil
}

// ExtractFromZipToUniqueTempFile extracts select paths for the given archive to a temporary directory, returning file openers for each file extracted.
func ExtractFromZipToUniqueTempFile(archivePath, dir string, paths ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(file *zip.File) error {
		tempfilePrefix := filepath.Base(filepath.Clean(file.Name)) + "-"

		tempFile, err := os.CreateTemp(dir, tempfilePrefix)
		if err != nil {
			return fmt.Errorf("unable to create temp file: %w", err)
		}
		// we shouldn't try and keep the tempfile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		defer tempFile.Close()

		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
		defer func() {
			err := zippedFile.Close()
			if err != nil {
				log.Errorf("unable to close source file=%q from zip=%q: %+v", file.Name, archivePath, err)
			}
		}()

		if file.FileInfo().IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.Name)
		}

		if err := safeCopy(tempFile, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name, archivePath, err)
		}

		results[file.Name] = Opener{path: tempFile.Name()}

		return nil
	}

	return results, TraverseFilesInZip(archivePath, visitor, paths...)
}

// ContentsFromZip extracts select paths for the given archive and returns a set of string contents for each path.
func ContentsFromZip(archivePath string, paths ...string) (map[string]string, error) {
	results := make(map[string]string)

	// don't allow for full traversal, only select traversal from given paths
	if len(paths) == 0 {
		return results, nil
	}

	visitor := func(file *zip.File) error {
		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
		}

		if file.FileInfo().IsDir() {
			return fmt.Errorf("unable to extract directories, only files: %s", file.Name)
		}

		var buffer bytes.Buffer
		if err := safeCopy(&buffer, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q for zip=%q: %w", file.Name, archivePath, err)
		}

		results[file.Name] = buffer.String()

		err = zippedFile.Close()
		if err != nil {
			return fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
		}
		return nil
	}

	return results, TraverseFilesInZip(archivePath, visitor, paths...)
}

// UnzipToDir extracts a zip archive to a target directory.
func UnzipToDir(archivePath, targetDir string) error {
	visitor := func(file *zip.File) error {
		joinedPath, err := safeJoin(targetDir, file.Name)
		if err != nil {
			return err
		}

		return extractSingleFile(file, joinedPath, archivePath)
	}

	return TraverseFilesInZip(archivePath, visitor)
}

// safeJoin ensures that any destinations do not resolve to a path above the prefix path.
func safeJoin(prefix string, dest ...string) (string, error) {
	joinResult := filepath.Join(append([]string{prefix}, dest...)...)
	cleanJoinResult := filepath.Clean(joinResult)
	if !strings.HasPrefix(cleanJoinResult, filepath.Clean(prefix)) {
		return "", &errZipSlipDetected{
			Prefix:   prefix,
			JoinArgs: dest,
		}
	}
	// why not return the clean path? the called may not be expected it from what should only be a join operation.
	return joinResult, nil
}

func extractSingleFile(file *zip.File, expandedFilePath, archivePath string) error {
	zippedFile, err := file.Open()
	if err != nil {
		return fmt.Errorf("unable to read file=%q from zip=%q: %w", file.Name, archivePath, err)
	}

	if file.FileInfo().IsDir() {
		err = os.MkdirAll(expandedFilePath, file.Mode())
		if err != nil {
			return fmt.Errorf("unable to create dir=%q from zip=%q: %w", expandedFilePath, archivePath, err)
		}
	} else {
		// Open an output file for writing
		outputFile, err := os.OpenFile(
			expandedFilePath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			file.Mode(),
		)
		if err != nil {
			return fmt.Errorf("unable to create dest file=%q from zip=%q: %w", expandedFilePath, archivePath, err)
		}

		if err := safeCopy(outputFile, zippedFile); err != nil {
			return fmt.Errorf("unable to copy source=%q to dest=%q for zip=%q: %w", file.Name, outputFile.Name(), archivePath, err)
		}

		err = outputFile.Close()
		if err != nil {
			return fmt.Errorf("unable to close dest file=%q from zip=%q: %w", outputFile.Name(), archivePath, err)
		}
	}

	err = zippedFile.Close()
	if err != nil {
		return fmt.Errorf("unable to close source file=%q from zip=%q: %w", file.Name, archivePath, err)
	}
	return nil
}
