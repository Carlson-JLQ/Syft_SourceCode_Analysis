package file

//该代码定义了用于表示可执行文件信息的结构体和类型。

// ExecutableFormat: 表示可执行文件格式的字符串类型。
// ELF: Executable and Linkable Format (ELF)
// MachO: Mach-O 格式 (Apple 系统)
// PE: Portable Executable 格式 (Windows 系统)
// RelocationReadOnly: 表示重定位只读状态的字符串类型。
// none: 没有重定位写保护
// partial: 部分重定位写保护
// full: 完全重定位写保护
type (
	ExecutableFormat   string
	RelocationReadOnly string
)

const (
	ELF   ExecutableFormat = "elf"
	MachO ExecutableFormat = "macho"
	PE    ExecutableFormat = "pe"

	RelocationReadOnlyNone    RelocationReadOnly = "none"
	RelocationReadOnlyPartial RelocationReadOnly = "partial"
	RelocationReadOnlyFull    RelocationReadOnly = "full"
)

// Executable:
//
// Format: 可执行文件格式 (ExecutableFormat)。
// SecurityFeatures (可选)：指向 ELFSecurityFeatures 结构体的指针，包含 ELF 文件的安全特性信息。
type Executable struct {
	// Format denotes either ELF, Mach-O, or PE
	Format ExecutableFormat `json:"format" yaml:"format" mapstructure:"format"`

	SecurityFeatures *ELFSecurityFeatures `json:"elfSecurityFeatures,omitempty" yaml:"elfSecurityFeatures" mapstructure:"elfSecurityFeatures"`
}

// ELFSecurityFeatures: 包含 ELF 文件的安全特性信息。
//
// SymbolTableStripped: 表示是否剥离符号表。
// StackCanary: 指向布尔值的指针，是否启用栈溢出保护 (Stack Canary)。
// NoExecutable: 是否启用不可执行标记 (NX)，防止代码注入攻击。
// RelocationReadOnly: 重定位只读状态 (RelocationReadOnly)，防止修改 GOT 表。
// PositionIndependentExecutable: 是否启用位置无关可执行 (PIE)，提高攻击难度。
// DynamicSharedObject: 是否为动态共享对象 (DSO)，即共享库。
// LlvmSafeStack (可选)：指向布尔值的指针，是否启用 LLVM SafeStack 保护机制。
// LlvmControlFlowIntegrity (可选)：指向布尔值的指针，是否启用控制流完整性 (CFI) 保护。
// ClangFortifySource (可选)：指向布尔值的指针，是否启用 Clang FortifySource 扩展集，用于检测常见库函数误用。
type ELFSecurityFeatures struct {
	SymbolTableStripped bool `json:"symbolTableStripped" yaml:"symbolTableStripped" mapstructure:"symbolTableStripped"`

	// classic protections

	StackCanary                   *bool              `json:"stackCanary,omitempty" yaml:"stackCanary" mapstructure:"stackCanary"`
	NoExecutable                  bool               `json:"nx" yaml:"nx" mapstructure:"nx"`
	RelocationReadOnly            RelocationReadOnly `json:"relRO" yaml:"relRO" mapstructure:"relRO"`
	PositionIndependentExecutable bool               `json:"pie" yaml:"pie" mapstructure:"pie"`
	DynamicSharedObject           bool               `json:"dso" yaml:"dso" mapstructure:"dso"`

	// LlvmSafeStack represents a compiler-based security mechanism that separates the stack into a safe stack for storing return addresses and other critical data, and an unsafe stack for everything else, to mitigate stack-based memory corruption errors
	// see https://clang.llvm.org/docs/SafeStack.html
	LlvmSafeStack *bool `json:"safeStack,omitempty" yaml:"safeStack" mapstructure:"safeStack"`

	// ControlFlowIntegrity represents runtime checks to ensure a program's control flow adheres to the legal paths determined at compile time, thus protecting against various types of control-flow hijacking attacks
	// see https://clang.llvm.org/docs/ControlFlowIntegrity.html
	LlvmControlFlowIntegrity *bool `json:"cfi,omitempty" yaml:"cfi" mapstructure:"cfi"`

	// ClangFortifySource is a broad suite of extensions to libc aimed at catching misuses of common library functions
	// see https://android.googlesource.com/platform//bionic/+/d192dbecf0b2a371eb127c0871f77a9caf81c4d2/docs/clang_fortify_anatomy.md
	ClangFortifySource *bool `json:"fortify,omitempty" yaml:"fortify" mapstructure:"fortify"`

	//// Selfrando provides function order shuffling to defend against ROP and other types of code reuse
	//// see https://github.com/runsafesecurity/selfrando
	// Selfrando *bool `json:"selfrando,omitempty" yaml:"selfrando" mapstructure:"selfrando"`
}
