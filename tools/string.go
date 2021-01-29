package tools

import (
	"fmt"
	"time"
)

func CalcRemainSec(challenge int64) int {
	return 30 - int(time.Now().Unix()-challenge*30)
}

func MakeSubTitle(challenge int64, code string) string {
	return fmt.Sprintf("Code: %s, Expires in %d second(s)", code, CalcRemainSec(challenge))
}

func MakeTitle(name, originName string) string {
	if len(name) > len(originName) {
		return name
	}

	return originName
}
