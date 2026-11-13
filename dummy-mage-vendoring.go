// +build useless

// This will never be built but it will be evaluated by 'go mod vendor'
// to ensure that all of mage is pulled in.

package main

import (
	"github.com/magefile/mage"
)

func main() {
}
