package syft

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/anchore/syft/syft/source"
)

// GetSource uses all of Syft's known source providers to attempt to resolve the user input to a usable source.Source
// GetSource 函数 是 syft 库用来解析用户输入并获取源数据的核心函数。
// 它尝试使用 syft 支持的所有源提供程序来解析用户输入，并返回一个可用的 source.Source 对象。
func GetSource(ctx context.Context, userInput string, cfg *GetSourceConfig) (source.Source, error) {
	//ctx: context.Context 对象，用于传递上下文信息。
	//userInput: 用户提供的字符串，代表要解析的源数据。
	//cfg: 可选的 GetSourceConfig 配置对象，用于配置解析行为。
	if cfg == nil {
		//如果 cfg 为空，则使用 DefaultGetSourceConfig 函数获取默认配置
		cfg = DefaultGetSourceConfig()
	}
	//根据配置和用户输入，调用 cfg.getProviders 方法获取可用于解析的Providers。
	providers, err := cfg.getProviders(userInput)
	//如果出错了，就返回err信息
	if err != nil {
		return nil, err
	}

	var errs []error
	var fileNotfound error

	// call each source provider until we find a valid source
	//逐个尝试解析
	//遍历 providers 列表中的每个源提供程序 p。
	//调用 p.Provide(ctx) 方法尝试解析源数据。
	//如果解析失败，则将错误信息添加到 errs 列表中。
	//特别处理 os.ErrNotExist 错误，将其单独保存到 fileNotfound 变量中。
	//如果解析成功，则检查配置中的 Platform 参数是否设置。
	//如果设置了 Platform 参数，并且解析出的源数据不是镜像类型，则返回错误信息。
	//如果解析成功且符合条件，则直接返回解析出的源数据 src 和 nil 错误。
	for _, p := range providers {
		src, err := p.Provide(ctx)
		if err != nil {
			err = eachError(err, func(err error) error {
				if errors.Is(err, os.ErrNotExist) {
					fileNotfound = err
					return nil
				}
				return err
			})
			if err != nil {
				errs = append(errs, err)
			}
		}
		if src != nil {
			// if we have a non-image type and platform is specified, it's an error
			if cfg.SourceProviderConfig.Platform != nil {
				meta := src.Describe().Metadata
				switch meta.(type) {
				case *source.ImageMetadata, source.ImageMetadata:
				default:
					return src, fmt.Errorf("platform specified with non-image source")
				}
			}
			return src, nil
		}
	}

	if fileNotfound != nil {
		errs = append([]error{fileNotfound}, errs...)
	}
	return nil, sourceError(userInput, errs...)
}

func sourceError(userInput string, errs ...error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("an error occurred attempting to resolve '%s': %w", userInput, errs[0])
	}
	errorTexts := ""
	for _, e := range errs {
		errorTexts += fmt.Sprintf("\n  - %s", e)
	}
	return fmt.Errorf("errors occurred attempting to resolve '%s':%s", userInput, errorTexts)
}

func eachError(err error, fn func(error) error) error {
	out := fn(err)
	// unwrap singly wrapped errors
	if e, ok := err.(interface {
		Unwrap() error
	}); ok {
		wrapped := e.Unwrap()
		got := eachError(wrapped, fn)
		// return the outer error if received the same wrapped error
		if errors.Is(got, wrapped) {
			return err
		}
		return got
	}
	// unwrap errors from errors.Join
	if errs, ok := err.(interface {
		Unwrap() []error
	}); ok {
		for _, e := range errs.Unwrap() {
			e = eachError(e, fn)
			if e != nil {
				out = errors.Join(out, e)
			}
		}
	}
	return out
}
