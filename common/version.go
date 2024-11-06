package common

import "fmt"

// 语义化的版本号 Semantic Versioning
const (
	versionX byte = 1
	versionY byte = 2
	versionZ byte = 0
)

// Version 获取 x.y.z 文本格式版本号
func Version() string {
	return fmt.Sprintf("%v.%v.%v", versionX, versionY, versionZ)
}
