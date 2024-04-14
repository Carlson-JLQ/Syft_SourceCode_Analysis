package sbom

import (
	"io"
)

type FormatID string

// String 方法可以将 FormatID 转换为普通字符串。
// String returns a string representation of the FormatID.
func (f FormatID) String() string {
	return string(f)
}

const AnyVersion = ""

// * `ID() FormatID`: 此方法应返回编码器的格式标识符 (`FormatID`)。
// * `Aliases() []string`: 此方法应返回格式的别名列表（可选）。
// * `Version() string`: 此方法应返回编码器支持的格式版本（可选）。
// * `Encode(io.Writer, SBOM) error`: 此方法接受一个 `io.Writer`（编码后的数据将写入其中）和一个 `SBOM` 对象（要编码的数据），并将 SBOM 数据编码为特定格式。
type FormatEncoder interface {
	ID() FormatID
	Aliases() []string
	Version() string
	Encode(io.Writer, SBOM) error
}

// * `Decode(io.Reader) (*SBOM, FormatID, string, error)`: 此方法接受一个 `io.Reader`（包含 SBOM 数据）并尝试对其进行解码。它返回指向 `SBOM` 对象（解码后的数据）的指针，格式标识符 (`FormatID`)，格式版本（可选），以及如果解码失败则返回错误。
// * `Identify(io.Reader) (FormatID, string)`: 此方法接受一个 `io.Reader` 并尝试识别 SBOM 数据的格式和版本，而无需完全解码它。它返回格式标识符 (`FormatID`) 和格式版本（可选）。
type FormatDecoder interface {
	// Decode will return an SBOM from the given reader. If the bytes are not a valid SBOM for the given format
	// then an error will be returned.
	Decode(io.Reader) (*SBOM, FormatID, string, error)

	// Identify will return the format ID and version for the given reader. Note: this does not validate the
	// full SBOM, only pulls the minimal information necessary to identify the format.
	Identify(io.Reader) (FormatID, string)
}
