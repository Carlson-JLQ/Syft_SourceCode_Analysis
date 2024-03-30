package cataloging

// DataGenerationConfig 结构体用于配置数据生成的选项。
// GenerateCPEs (类型为 bool)： 指定是否生成 CPE (Common Platform Enumeration) 字符串。
type DataGenerationConfig struct {
	GenerateCPEs bool `yaml:"generate-cpes" json:"generate-cpes" mapstructure:"generate-cpes"`
}

// DefaultDataGenerationConfig()： 返回一个默认的 DataGenerationConfig 配置。
// 默认情况下，会生成 CPE 字符串。
func DefaultDataGenerationConfig() DataGenerationConfig {
	return DataGenerationConfig{
		GenerateCPEs: true,
	}
}

func (c DataGenerationConfig) WithGenerateCPEs(generate bool) DataGenerationConfig {
	c.GenerateCPEs = generate
	return c
}

//CPE 是 Common Platform Enumeration 的缩写，中文名称为通用平台枚举。它是一种用于识别和分类 IT 资产的标准化方法。
//CPE 字符串由一系列命名空间和值组成，可以描述软件、硬件、固件和其他类型的 IT 产品。
//CPE 的组成：
//
//命名空间： 定义 CPE 字符串中特定部分的含义。例如，cpe:2.3:a 命名空间用于描述软件应用程序。
//值： 提供特定命名空间下的详细信息。例如，cpe:2.3:a:apache:tomcat:8.0.52 描述了 Apache Tomcat 8.0.52 软件应用程序。
