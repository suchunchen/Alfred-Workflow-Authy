package cmd

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/momaek/authy/totp"

	"github.com/spf13/cobra"
)

// fuzzCmd represents the fuzz command
var recordCmd = &cobra.Command{
	Use:   "record",
	Short: "Fuzzy search your otp tokens(case-insensitive)",
	Long: `Fuzzy search your otp tokens(case-insensitive)

First time(or after clean cache) , need your authy main password`,
	Run: func(cmd *cobra.Command, args []string) {
		recordCallback(args)
	},
}

func init() {
	rootCmd.AddCommand(recordCmd)
}

func getRecords() map[string]int {
	var records = make(map[string]int)

	filePath := filepath.Join(getExecutablePath(), "data", "records.json")
	if b, _ := ioutil.ReadFile(filePath); len(b) > 0 {
		_ = json.Unmarshal(b, &records)
	}

	return records
}

func getExecutablePath() string {
	ex, _ := os.Executable()
	return filepath.Dir(ex)
}

func recordCallback(args []string) {
	if len(args) == 0 {
		return
	}

	devInfo, err := LoadExistingDeviceInfo()
	if err != nil {
		if os.IsNotExist(err) {
			devInfo, err = newRegistrationDevice()
			if err != nil {
				return
			}
		} else {
			log.Println("load device info failed", err)
			return
		}
	}

	tokens, err := loadCachedTokens()
	if err != nil {
		tokens, err = getTokensFromAuthyServer(&devInfo)
		if err != nil {
			log.Fatal("get tokens failed", err)
		}
	}

	for _, token := range tokens {
		for _, code := range totp.GetTotpCode(token.Secret, token.Digital) {
			if code == args[0] {
				records := getRecords()
				records[token.OriginalName.String()] += 1

				if b, _ := json.Marshal(records); len(b) > 0 {
					_ = ioutil.WriteFile(filepath.Join(getExecutablePath(), "data", "records.json"), b, os.ModePerm)
				}

				break
			}
		}
	}
}
