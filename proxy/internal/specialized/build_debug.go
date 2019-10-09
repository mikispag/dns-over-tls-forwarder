// +build debug

package specialized

import "fmt"

func printf(fm string, i ...interface{}) {
	fmt.Printf(fm, i...)
	fmt.Println()
}
