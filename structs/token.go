package structs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/momaek/authy/images"

	"github.com/momaek/authy/tools"
	"github.com/momaek/authy/totp"
)

type FullName string

func (f FullName) AppName() string {
	if strings.Contains(f.String(), ":") {
		return strings.Split(f.String(), ":")[0]
	}
	return ""
}

func (f FullName) String() string {
	return string(f)
}

// Token save in cache
type Token struct {
	Name         string   `json:"name"`
	OriginalName FullName `json:"original_name"`
	Digital      int      `json:"digital"`
	Secret       string   `json:"secret"`
	Period       int      `json:"period"`
	Score        int      `json:"-"`
}

// Tokens for
type Tokens []Token

func (ts Tokens) String(i int) string {
	if len(ts[i].Name) > len(ts[i].OriginalName) {
		return ts[i].Name
	}

	return ts[i].OriginalName.String()
}

// Len implement fuzzy.Source
func (ts Tokens) Len() int {
	return len(ts)
}

func (ts Tokens) Echo2Alfred() bool {
	if len(ts) == 0 {
		return false
	}

	outputs := make([]AlfredOutput, 0)
	challenge := totp.GetChallenge()
	appNameExisted := make(map[string]struct{})

	for _, tk := range ts {
		codes := totp.GetTotpCode(tk.Secret, tk.Digital)
		var appName = tk.OriginalName.AppName()
		if _, ok := appNameExisted[appName]; ok {
			// 如果已重名，那就用全称
			appName = tk.OriginalName.String()
		} else {
			appNameExisted[appName] = struct{}{}
		}

		outputs = append(outputs, AlfredOutput{
			Title:    appName,
			Subtitle: tools.MakeSubTitle(challenge, codes[1]),
			Arg:      codes[1],
			Valid:    true,
			Icon: Icon{
				Type: "",
				Path: images.AppIconDict[appName],
			},
		})
	}

	b, _ := json.Marshal(map[string]interface{}{"items": outputs})
	fmt.Println(string(b))
	return true
}
