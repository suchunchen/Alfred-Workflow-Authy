package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/momaek/authy/tools"

	"github.com/momaek/authy/structs"

	//"time"

	"github.com/alexzorin/authy"
	"github.com/momaek/authy/totp"
	"github.com/sahilm/fuzzy"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

// fuzzCmd represents the fuzz command
var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Fuzzy search your otp tokens(case-insensitive)",
	Long: `Fuzzy search your otp tokens(case-insensitive)

First time(or after clean cache) , need your authy main password`,
	Run: func(cmd *cobra.Command, args []string) {
		fuzzySearch(args)
	},
}

var alfredCount *int

func init() {
	rootCmd.AddCommand(fuzzCmd)
	alfredCount = fuzzCmd.Flags().CountP("alfred", "a", "Specify Output Mode AlfredWorkflow")
}

func fuzzySearch(args []string) {
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
	// 没有关键词，输出全部
	if len(args) == 0 {
		tokens.Echo2Alfred()
		return
	}

	results := fuzzy.FindFrom(args[0], structs.Tokens(tokens))
	if alfredCount != nil && *alfredCount > 0 && len(results) > 0 {
		tokensFound := make(structs.Tokens, 0)
		for _, v := range results {
			tokensFound = append(tokensFound, tokens[v.Index])
		}
		tokensFound.Echo2Alfred()
		return
	}

	prettyPrintResult(results, tokens)
}

const (
	// Black black
	Black = "\033[1;30m%s\033[0m"
	// Red red
	Red = "\033[1;31m%s\033[0m"
	// Green green
	Green = "\033[1;32m%s\033[0m"
	// Yellow yellow
	Yellow = "\033[1;33m%s\033[0m"
	// Purple purple
	Purple = "\033[1;34m%s\033[0m"
	// Magenta magenta
	Magenta = "\033[1;35m%s\033[0m"
	// Teal teal
	Teal = "\033[1;36m%s\033[0m"
	// White white
	White = "\033[1;37m%s\033[0m"
	// DebugColor debug color
	DebugColor = "\033[0;36m%s\033[0m"
)

func prettyPrintResult(results fuzzy.Matches, tokens []structs.Token) {
	fmt.Printf("\n")
	for _, r := range results {
		tk := tokens[r.Index]
		codes := totp.GetTotpCode(tk.Secret, tk.Digital)
		challenge := totp.GetChallenge()
		title := tools.MakeTitle(tk.Name, tk.OriginalName.String())
		fmt.Printf("- Title: "+Green+"\n", title)
		fmt.Printf("- Code: "+Teal+" Expires in "+Red+"(s)\n\n", codes[1], fmt.Sprint(tools.CalcRemainSec(challenge)))
	}
	return
}

const cacheFileName = ".authycache.json"

func loadCachedTokens() (tks structs.Tokens, err error) {
	fpath, err := ConfigPath(cacheFileName)
	if err != nil {
		return
	}

	f, err := os.Open(fpath)
	if err != nil {
		return
	}

	defer f.Close()
	err = json.NewDecoder(f).Decode(&tks)
	return
}

func saveTokens(tks []structs.Token) (err error) {
	regrPath, err := ConfigPath(cacheFileName)
	if err != nil {
		return
	}

	f, err := os.OpenFile(regrPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return
	}

	defer f.Close()
	err = json.NewEncoder(f).Encode(&tks)
	return
}

func getTokensFromAuthyServer(devInfo *DeviceRegistration) (tks []structs.Token, err error) {
	client, err := authy.NewClient()
	if err != nil {
		log.Fatalf("Create authy API client failed %+v", err)
	}

	apps, err := client.QueryAuthenticatorApps(nil, devInfo.UserID, devInfo.DeviceID, devInfo.Seed)
	if err != nil {
		log.Fatalf("Fetch authenticator apps failed %+v", err)
	}

	if !apps.Success {
		log.Fatalf("Fetch authenticator apps failed %+v", apps)
	}

	tokens, err := client.QueryAuthenticatorTokens(nil, devInfo.UserID, devInfo.DeviceID, devInfo.Seed)
	if err != nil {
		log.Fatalf("Fetch authenticator tokens failed %+v", err)
	}

	if !tokens.Success {
		log.Fatalf("Fetch authenticator tokens failed %+v", tokens)
	}

	if len(devInfo.MainPassword) == 0 {
		fmt.Print("\nPlease input Authy main password: ")
		pp, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Get password failed %+v", err)
		}

		devInfo.MainPassword = strings.TrimSpace(string(pp))
		SaveDeviceInfo(*devInfo)
	}

	tks = []structs.Token{}
	for _, v := range tokens.AuthenticatorTokens {
		secret, err := v.Decrypt(devInfo.MainPassword)
		if err != nil {
			log.Fatalf("Decrypt token failed %+v", err)
		}

		tks = append(tks, structs.Token{
			Name:         v.Name,
			OriginalName: structs.FullName(v.OriginalName),
			Digital:      v.Digits,
			Secret:       secret,
		})
	}

	for _, v := range apps.AuthenticatorApps {
		secret, err := v.Token()
		if err != nil {
			log.Fatal("Get secret from app failed", err)
		}

		tks = append(tks, structs.Token{
			Name:    v.Name,
			Digital: v.Digits,
			Secret:  secret,
			Period:  10,
		})
	}

	saveTokens(tks)
	return
}
