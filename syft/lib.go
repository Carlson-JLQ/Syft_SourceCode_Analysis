/*
Package syft is a "one-stop-shop" for helper utilities for all major functionality provided by child packages of the syft library.

Here is what the main execution path for syft does:

 1. Parse a user image string to get a stereoscope image.Source object
 2. Invoke all catalogers to catalog the image, adding discovered packages to a single catalog object
 3. Invoke one or more encoders to output contents of the catalog

A Source object encapsulates the image object to be cataloged and the user options (catalog all layers vs. squashed layer),
providing a way to inspect paths and file content within the image. The Source object, not the image object, is used
throughout the main execution path. This abstraction allows for decoupling of what is cataloged (a docker image, an OCI
image, a filesystem, etc) and how it is cataloged (the individual catalogers).

Similar to the cataloging process, Linux distribution identification is also performed based on what is discovered within the image.
*/
/*
Syft 软件包是用于访问 syft 库子包所有主要功能的辅助实用程序的 "一站式商店"。

以下是 syft 的主要执行流程：

解析用户镜像字符串以获取立体的镜像image.Source 对象
调用所有 cataloger 来编目镜像，将发现的包添加到单个 catalog 对象中
调用一个或多个编码器来输出目录内容
Source 对象封装了要编目的镜像对象和用户选项（编目所有层 vs. 压缩层），
提供了一种检查镜像内路径和文件内容的方法。整个主执行路径中使用 Source 对象，
而不是镜像对象本身。这种抽象允许解耦要编目的是什么（docker 镜像、OCI 镜像、文件系统等）以及如何编目（各个编目器）。

类似于编目过程，Linux 发行版识别也基于镜像中发现的内容进行。
*/
package syft

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
)

// SetLogger sets the logger object used for all syft logging calls.
// SetLogger 函数用于设置所有 syft 日志调用的日志记录器对象
func SetLogger(logger logger.Logger) {
	log.Set(logger)
}

// SetBus sets the event bus for all syft library bus publish events onto (in-library subscriptions are not allowed).
// SetBus 函数用于设置 syft 库事件总线，但需要注意一些限制。
// SetBus: 该部分表示这是一个函数名，用来设置事件总线。
// event bus: 事件总线是一种用于组件间通信的机制。组件可以向总线发布事件，其他组件可以订阅这些事件并作出相应处理。
// syft library bus publish events onto: 表示 SetBus 函数的作用是设置事件总线，用于接收 syft 库内部发布的事件。
// (in-library subscriptions are not allowed): 这部分说明了一个限制，即不允许在 syft 库内部订阅事件总线上的事件。换句话说，syft 库内部的组件只能发布事件，而不能订阅事件。
func SetBus(b *partybus.Bus) {
	bus.Set(b)
	//*partybus.Bus 是来自 partybus 库的结构体，它代表一个事件总线。
	//事件总线是一种用于组件间通信的机制，允许组件发布事件并让其他组件订阅这些事件并作出相应处理。
}
