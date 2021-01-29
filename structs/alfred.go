package structs

type Icon struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// AlfredOutput alfred workflow output
type AlfredOutput struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Arg      string `json:"arg"`
	Icon     Icon   `json:"icon"`
	Valid    bool   `json:"valid"`
	Text     struct {
		Copy string `json:"copy"`
	} `json:"text"`
}
