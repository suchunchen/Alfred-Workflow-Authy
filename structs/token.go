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
	return string(f)
}

func (f FullName) Account() string {
	if strings.Contains(f.String(), ":") {
		return strings.Split(f.String(), ":")[1]
	}
	return string(f)
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

	for _, tk := range ts {
		codes := totp.GetTotpCode(tk.Secret, tk.Digital)
		outputs = append(outputs, AlfredOutput{
			Title:    tk.OriginalName.Account(),
			Subtitle: tools.MakeSubTitle(challenge, codes[1]),
			Arg:      codes[1],
			Valid:    true,
			Icon: Icon{
				Type: "",
				Path: images.AppIconDict[tk.OriginalName.AppName()],
			},
		})
	}

	b, _ := json.Marshal(map[string]interface{}{"items": outputs})
	fmt.Println(string(b))
	return true
}
