package main

import (
	"fmt"
	"os"
	"strings"
)

const msg = "Please try again!\n"
const promote = "Please input flag: "
const congratulation = "Congratulations!\n"

/// flag{I_be1ieve_PHP_is_the_best_1anguage_forever!}
/// It's recommended to link the folder into ${GOPATH}
/// CGO_ENABLED=0 GOOS=windows GOARCH=386 go build --ldflags "-s -w" re1.go
func main() {
	fmt.Print(promote)
	var input string
	n, err := fmt.Scanf("%s", &input)
	if nil != err {
		exit()
	}
	if n <= 0 {
		exit()
	}
	if len(input) != 49 {
		exit()
	}
	if !(strings.HasPrefix(input, "flag{") && strings.HasSuffix(input, "}")) {
		exit()
	}
	var data = []byte(input)
	data = data[5:48]
	if ^data[0] != 182 { exit() }
	if ^data[1] != 160 { exit() }
	if ^data[2] != 157 { exit() }
	if ^data[3] != 154 { exit() }
	if ^data[4] != 206 { exit() }
	if ^data[5] != 150 { exit() }
	if ^data[6] != 154 { exit() }
	if ^data[7] != 137 { exit() }
	if ^data[8] != 154 { exit() }
	if ^data[9] != 160 { exit() }
	if ^data[10] != 175 { exit() }
	if ^data[11] != 183 { exit() }
	if ^data[12] != 175 { exit() }
	if ^data[13] != 160 { exit() }
	if ^data[14] != 150 { exit() }
	if ^data[15] != 140 { exit() }
	if ^data[16] != 160 { exit() }
	if ^data[17] != 139 { exit() }
	if ^data[18] != 151 { exit() }
	if ^data[19] != 154 { exit() }
	if ^data[20] != 160 { exit() }
	if ^data[21] != 157 { exit() }
	if ^data[22] != 154 { exit() }
	if ^data[23] != 140 { exit() }
	if ^data[24] != 139 { exit() }
	if ^data[25] != 160 { exit() }
	if ^data[26] != 206 { exit() }
	if ^data[27] != 158 { exit() }
	if ^data[28] != 145 { exit() }
	if ^data[29] != 152 { exit() }
	if ^data[30] != 138 { exit() }
	if ^data[31] != 158 { exit() }
	if ^data[32] != 152 { exit() }
	if ^data[33] != 154 { exit() }
	if ^data[34] != 160 { exit() }
	if ^data[35] != 153 { exit() }
	if ^data[36] != 144 { exit() }
	if ^data[37] != 141 { exit() }
	if ^data[38] != 154 { exit() }
	if ^data[39] != 137 { exit() }
	if ^data[40] != 154 { exit() }
	if ^data[41] != 141 { exit() }
	if ^data[42] != 222 { exit() }
	fmt.Print(congratulation)
}

func exit() {
	fmt.Print(msg)
	os.Exit(-1)
}