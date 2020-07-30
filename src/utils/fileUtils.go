package utils

import "io/ioutil"

func GetFileContent(path string) {
	ioutil.ReadFile(path)
}
