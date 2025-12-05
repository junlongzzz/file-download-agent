package common

import "fmt"

// 语义化的版本号 Semantic Versioning
const (
	versionX byte = 2
	versionY byte = 1
	versionZ byte = 1
)

// Version 获取 x.y.z 文本格式版本号
func Version() string {
	return fmt.Sprintf("%v.%v.%v", versionX, versionY, versionZ)
}
