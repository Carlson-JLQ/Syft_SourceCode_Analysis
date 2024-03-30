package artifact

// 这部分代码定义了软件包之间关系的类型
const (
	// OwnershipByFileOverlapRelationship (supports package-to-package linkages) indicates that the parent package
	// claims ownership of a child package since the parent metadata indicates overlap with a location that a
	// cataloger found the child package by. This relationship must be created only after all package cataloging
	// has been completed.
	//表示父包通过文件重叠的方式拥有子包。
	OwnershipByFileOverlapRelationship RelationshipType = "ownership-by-file-overlap"

	// EvidentByRelationship is a package-to-file relationship indicating the that existence of this package is evident
	// by the contents of a file. This does not necessarily mean that the package is contained within that file
	// or that it is described by it (either or both may be true). This does NOT map to an existing specific SPDX
	// relationship. Instead, this should be mapped to OTHER and the comment field be updated to show EVIDENT_BY.
	//表示通过文件的内容可以得知包的存在，但不一定包含在文件中或被文件描述。
	EvidentByRelationship RelationshipType = "evident-by"

	// ContainsRelationship (supports any-to-any linkages) is a proxy for the SPDX 2.2 CONTAINS relationship.
	//表示一个包包含另一个包 (类似于 SPDX 2.2 标准中的 CONTAINS 关系)
	ContainsRelationship RelationshipType = "contains"

	// DependencyOfRelationship is a proxy for the SPDX 2.2.1 DEPENDENCY_OF	relationship.
	//表示一个包依赖于另一个包 (类似于 SPDX 2.2.1 标准中的 DEPENDENCY_OF 关系)。
	DependencyOfRelationship RelationshipType = "dependency-of"

	// DescribedByRelationship is a proxy for the SPDX 2.2.2 DESCRIBED_BY relationship.
	//表示一个包被另一个包描述 (类似于 SPDX 2.2.2 标准中的 DESCRIBED_BY 关系)。
	DescribedByRelationship RelationshipType = "described-by"
)

// 函数返回所有支持的关系类型列表
func AllRelationshipTypes() []RelationshipType {
	return []RelationshipType{
		OwnershipByFileOverlapRelationship,
		ContainsRelationship,
		DependencyOfRelationship,
		DescribedByRelationship,
	}
}

type RelationshipType string

type Relationship struct {
	From Identifiable
	To   Identifiable
	Type RelationshipType
	Data interface{}
}
