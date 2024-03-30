package cataloging

// RelationshipsConfig 结构体用于配置包关系生成的选项。
type RelationshipsConfig struct {
	// PackageFileOwnership will include package-to-file relationships that indicate which files are owned by which packages.
	//指定是否在包关系中包含包到文件的拥有关系。例如，可以标识哪些文件属于特定的包。
	PackageFileOwnership bool `yaml:"package-file-ownership" json:"package-file-ownership" mapstructure:"package-file-ownership"`

	// PackageFileOwnershipOverlap will include package-to-package relationships that indicate one package is owned by another due to files claimed to be owned by one package are also evidence of another package's existence.
	// For example, if an RPM package is installed and claims to own /etc/app/package.lock and a separate NPM package was discovered by cataloging /etc/app/package.lock, then the two packages will
	// have ownership overlap relationship.
	//指定是否在包关系中包含因文件拥有关系而产生的包到包的重叠关系。例如，如果两个包都声称拥有同一个文件，则它们之间存在重叠关系。
	PackageFileOwnershipOverlap bool `yaml:"package-file-ownership-overlap" json:"package-file-ownership-overlap" mapstructure:"package-file-ownership-overlap"`

	// ExcludeBinaryPackagesWithFileOwnershipOverlap will exclude binary packages from the package catalog that are evident by files also owned by another package.
	// For example, if a binary package representing the /bin/python binary is discovered and there is a python RPM package installed which claims to
	// orn /bin/python, then the binary package will be excluded from the catalog altogether if this configuration is set to true.
	//指定是否将因文件拥有关系重叠而从包目录中排除二进制包。例如，如果存在一个单独的二进制包和一个 RPM 包，它们都声称拥有同一个可执行文件，那么根据此配置项，可以将二进制包排除在外。
	ExcludeBinaryPackagesWithFileOwnershipOverlap bool `yaml:"exclude-binary-packages-with-file-ownership-overlap" json:"exclude-binary-packages-with-file-ownership-overlap" mapstructure:"exclude-binary-packages-with-file-ownership-overlap"`
}

// DefaultRelationshipsConfig()： 返回一个默认的 RelationshipsConfig 配置。
// 默认情况下，所有选项都设置为 true，即会生成所有类型的包关系。
func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		PackageFileOwnership:                          true,
		PackageFileOwnershipOverlap:                   true,
		ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
	}
}

func (c RelationshipsConfig) WithPackageFileOwnership(ownership bool) RelationshipsConfig {
	c.PackageFileOwnership = ownership
	return c
}

func (c RelationshipsConfig) WithPackageFileOwnershipOverlap(overlap bool) RelationshipsConfig {
	c.PackageFileOwnershipOverlap = overlap
	return c
}

func (c RelationshipsConfig) WithExcludeBinaryPackagesWithFileOwnershipOverlap(exclude bool) RelationshipsConfig {
	c.ExcludeBinaryPackagesWithFileOwnershipOverlap = exclude
	return c
}
