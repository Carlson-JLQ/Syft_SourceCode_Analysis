package format

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/sbom"
)

// AllVersions：这是一个常量字符串，代表支持所有版本的 SBOM 格式（例如，CycloneDX JSON/XML、SPDX JSON/tag-value）
const AllVersions = "all-versions"

// 此类型用于配置各种 SBOM 格式的编码器。它包含了多个嵌套的类型，分别用于配置模板、Syft JSON、SPDX JSON/tag-value、CycloneDX JSON/XML 等格式的编码器。
type EncodersConfig struct {
	Template      template.EncoderConfig
	SyftJSON      syftjson.EncoderConfig
	SPDXJSON      spdxjson.EncoderConfig
	SPDXTagValue  spdxtagvalue.EncoderConfig
	CyclonedxJSON cyclonedxjson.EncoderConfig
	CyclonedxXML  cyclonedxxml.EncoderConfig
}

// 此函数返回可用于编码 SBOM 数据的编码器列表。它首先调用 DefaultEncodersConfig 函数获取默认配置，然后调用该配置对象的 Encoders 方法来生成并返回编码器列表。
func Encoders() []sbom.FormatEncoder {
	encs, _ := DefaultEncodersConfig().Encoders()
	return encs
}

// DefaultEncodersConfig 函数：此函数返回一个默认的 EncodersConfig 配置对象。它为每个支持的格式设置了默认的配置，并特别将 SPDXJSON、SPDXTagValue、CyclonedxJSON 和 CyclonedxXML 的版本设置为 AllVersions，表示支持所有版本。
func DefaultEncodersConfig() EncodersConfig {
	cfg := EncodersConfig{
		Template:      template.DefaultEncoderConfig(),
		SyftJSON:      syftjson.DefaultEncoderConfig(),
		SPDXJSON:      spdxjson.DefaultEncoderConfig(),
		SPDXTagValue:  spdxtagvalue.DefaultEncoderConfig(),
		CyclonedxJSON: cyclonedxjson.DefaultEncoderConfig(),
		CyclonedxXML:  cyclonedxxml.DefaultEncoderConfig(),
	}

	// empty value means to support all versions
	cfg.SPDXJSON.Version = AllVersions
	cfg.SPDXTagValue.Version = AllVersions
	cfg.CyclonedxJSON.Version = AllVersions
	cfg.CyclonedxXML.Version = AllVersions

	return cfg
}

// (o EncodersConfig) Encoders() ([]sbom.FormatEncoder, error) 函数：此方法用于根据 EncodersConfig 配置生成编码器列表。它会遍历配置中的各个格式，并根据配置生成相应的编码器。例如，如果配置了模板路径，则会生成模板格式的编码器。
// 该方法使用了嵌套的 encodersList 类型来收集生成的编码器和遇到的错误。
// 对于支持多版本的格式（CycloneDX JSON/XML、SPDX JSON/tag-value），它会根据配置 (AllVersions 或指定版本) 循环创建每个版本的编码器。
// 在生成编码器过程中，如果遇到任何错误，则会使用 github.com/hashicorp/go-multierror 库将错误添加到 encodersList 的 err 字段中。
func (o EncodersConfig) Encoders() ([]sbom.FormatEncoder, error) {
	//encodersList 类型：这是一个辅助类型，用于在生成编码器列表的过程中收集生成的编码器 (encoders) 和遇到的错误 (err)。
	var l encodersList

	if o.Template.TemplatePath != "" {
		l.addWithErr(template.ID)(o.templateEncoders())
	}

	l.addWithErr(syftjson.ID)(o.syftJSONEncoders())
	l.add(table.ID)(table.NewFormatEncoder())
	l.add(text.ID)(text.NewFormatEncoder())
	l.add(github.ID)(github.NewFormatEncoder())
	l.addWithErr(cyclonedxxml.ID)(o.cyclonedxXMLEncoders())
	l.addWithErr(cyclonedxjson.ID)(o.cyclonedxJSONEncoders())
	l.addWithErr(spdxjson.ID)(o.spdxJSONEncoders())
	l.addWithErr(spdxtagvalue.ID)(o.spdxTagValueEncoders())

	return l.encoders, l.err
}

func (o EncodersConfig) templateEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := template.NewFormatEncoder(o.Template)
	return []sbom.FormatEncoder{enc}, err
}

func (o EncodersConfig) syftJSONEncoders() ([]sbom.FormatEncoder, error) {
	enc, err := syftjson.NewFormatEncoderWithConfig(o.SyftJSON)
	return []sbom.FormatEncoder{enc}, err
}

func (o EncodersConfig) cyclonedxXMLEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.CyclonedxXML

	var versions []string
	if cfg.Version == AllVersions {
		versions = cyclonedxxml.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := cyclonedxxml.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) cyclonedxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.CyclonedxJSON

	var versions []string
	if cfg.Version == AllVersions {
		versions = cyclonedxjson.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) spdxJSONEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.SPDXJSON

	var versions []string
	if cfg.Version == AllVersions {
		versions = spdxjson.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := spdxjson.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

func (o EncodersConfig) spdxTagValueEncoders() ([]sbom.FormatEncoder, error) {
	var (
		encs []sbom.FormatEncoder
		errs error
	)

	cfg := o.SPDXTagValue

	var versions []string
	if cfg.Version == AllVersions {
		versions = spdxtagvalue.SupportedVersions()
	} else {
		versions = []string{cfg.Version}
	}

	for _, v := range versions {
		cfg.Version = v
		enc, err := spdxtagvalue.NewFormatEncoderWithConfig(cfg)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			encs = append(encs, enc)
		}
	}
	return encs, errs
}

type encodersList struct {
	encoders []sbom.FormatEncoder
	err      error
}

func (l *encodersList) addWithErr(name sbom.FormatID) func([]sbom.FormatEncoder, error) {
	return func(encs []sbom.FormatEncoder, err error) {
		if err != nil {
			l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: %w", name, err))
			return
		}
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}

func (l *encodersList) add(name sbom.FormatID) func(...sbom.FormatEncoder) {
	return func(encs ...sbom.FormatEncoder) {
		for _, enc := range encs {
			if enc == nil {
				l.err = multierror.Append(l.err, fmt.Errorf("unable to configure %q format encoder: nil encoder returned", name))
				continue
			}
			l.encoders = append(l.encoders, enc)
		}
	}
}
