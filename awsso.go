package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/psanford/awsso-agent/browser"
	"github.com/psanford/awsso-agent/client"
	"github.com/psanford/awsso-agent/config"
	"github.com/psanford/awsso-agent/messages"
	"github.com/psanford/awsso-agent/server"
	"github.com/psanford/awsso-agent/u2f"
	"github.com/spf13/cobra"
)

var (
	profileID             string
	execCmd               string
	printEnv              bool
	webConsole            bool
	timeoutMinutesSession int
	accountIDF            string
	roleNameF             string
	accountNameF          string
	csvF                  bool

	rootCmd = &cobra.Command{
		Use:   "awsso",
		Short: "AWS SSO agent tools",
	}
)

func main() {
	profileID = os.Getenv("AWSSO_PROFILE_ID")

	rootCmd.PersistentFlags().StringVarP(&profileID, "profile", "p", "", "Profile ID to use (defaults to first in config file)")

	rootCmd.RegisterFlagCompletionFunc("profile", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		c := config.LoadConfig()
		var ids []string
		for _, prof := range c.Profile {
			ids = append(ids, prof.ID)
		}
		return ids, cobra.ShellCompDirectiveNoFileComp
	})

	rootCmd.AddCommand(fidoRegisterCommand())
	rootCmd.AddCommand(loginCommand())
	rootCmd.AddCommand(serverCommand())
	rootCmd.AddCommand(sessionCommand())
	rootCmd.AddCommand(tokenCommand())
	rootCmd.AddCommand(credentialHelperCommand())
	rootCmd.AddCommand(listAccountsCommand())
	rootCmd.AddCommand(listProfilesCommand())
	rootCmd.AddCommand(startURLCommand())

	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func serverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "create a server",
		Run:   serverAction,
	}
}

func serverAction(cmd *cobra.Command, args []string) {
	conf := config.LoadConfig()
	s := server.New(&conf)
	err := s.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "login command",
		Run:   loginAction,
	}
}

func loginAction(cmd *cobra.Command, args []string) {
	client := client.NewClient()

	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	err = client.Login(profileID)
	if err != nil {
		log.Fatalf("Login error: %s", err)
	}

	log.Println("ok")
}

func startURLCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "start-url",
		Short: "Show start url",
		Run:   startURLAction,
	}
}

func startURLAction(cmd *cobra.Command, args []string) {
	conf := config.LoadConfig()
	profile, err := conf.FindProfile(profileID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(profile.StartUrl)
}

func sessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "create a session",
		Run:   sessionAction,
	}

	cmd.Flags().StringVarP(&accountIDF, "account-id", "", "", "Account ID")
	cmd.Flags().StringVarP(&roleNameF, "role", "", "", "Role Name")
	cmd.Flags().StringVarP(&accountNameF, "name", "", "", "Account Name (friendly)")
	cmd.Flags().BoolVarP(&printEnv, "print", "", false, "Print ENV settings")
	cmd.Flags().BoolVarP(&webConsole, "web", "", false, "Open web console with session credentials")
	cmd.Flags().IntVarP(&timeoutMinutesSession, "timeout-minutes", "", 30, "Session Timeout in minutes")
	cmd.Flags().StringVarP(&execCmd, "exec", "", "", "Exec command instead of dropping to shell")

	cmd.ValidArgsFunction = sessionCompletions

	return cmd
}

func sessionCompletions(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	accounts := config.CachedAccounts(profileID)

	var completions []string
	for _, account := range accounts {
		if strings.HasPrefix(account.String(), toComplete) {
			completions = append(completions, account.String())
		}
		if strings.HasPrefix(account.AccountID, toComplete) {
			completions = append(completions, account.AccountID)
		}
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}

func sessionAction(cmd *cobra.Command, args []string) {
	var (
		accountID   string
		roleName    string
		accountName string
	)

	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	if accountIDF != "" && roleNameF != "" {
		accountID = accountIDF
		roleName = roleNameF
		accountName = accountNameF
	} else if len(args) == 1 {
		given := args[0]

		validAccounts := config.CachedAccounts(profileID)
		if len(validAccounts) == 0 {
			larr, err := client.ListAccountsRoles(profileID)
			if err != nil {
				log.Fatalf("Failed to find any valid accounts either from cache or from ListAccounts")
			}
			validAccounts = larr.Accounts

		}
		for _, acct := range validAccounts {
			if given == acct.String() || given == acct.AccountID {
				accountID = acct.AccountID
				accountName = acct.AccountName
				roleName = acct.RoleName
				break
			}
		}
	} else {
		log.Fatalf("usage: session <account_id|long-account-id> [--account-id <id>, --role <role>, --name <friendly-name>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	userPresenceBypassToken := os.Getenv("AWSSO_TOKEN")
	creds, err := client.Session(profileID, accountID, roleName, accountName, userPresenceBypassToken)
	if err != nil {
		log.Fatal(err)
	}

	if accountName == "" {
		accountName = fmt.Sprintf("%s-%s", accountID, roleName)
	}

	startEnvOrPrint(creds, accountName)
}

func startEnvOrPrint(creds *messages.Credentials, name string) {
	if printEnv {
		fmt.Printf("  export AWS_ACCESS_KEY_ID=%s\n", *creds.AccessKeyId)
		fmt.Printf("  export AWS_SECRET_ACCESS_KEY=%s\n", *creds.SecretAccessKey)
		fmt.Printf("  export AWS_SESSION_TOKEN=%s\n", *creds.SessionToken)
		fmt.Printf("  export AWS_DEFAULT_REGION=\"%s\"", creds.Region)
		fmt.Printf("  export AWSSO_PROFILE=\"%s\"", name)
		fmt.Printf("  export AWSSO_SESSION_EXPIRATION=\"%d\"", creds.Expiration.Unix())

		fmt.Printf(`  export PS1="(awsso-%s)  \\[\\033[01;35m\\]\\w\\[\\033[00m\\]\\$ "`, name)
		fmt.Println()
	} else if webConsole {

		jsonTxt, err := json.Marshal(map[string]string{
			"sessionId":    *creds.AccessKeyId,
			"sessionKey":   *creds.SecretAccessKey,
			"sessionToken": *creds.SessionToken,
		})
		if err != nil {
			log.Fatal(err)
		}

		loginURLPrefix := "https://signin.aws.amazon.com/federation"
		req, err := http.NewRequest("GET", loginURLPrefix, nil)
		if err != nil {
			log.Fatal(err)
		}

		q := req.URL.Query()
		q.Add("Action", "getSigninToken")
		q.Add("Session", string(jsonTxt))

		req.URL.RawQuery = q.Encode()

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(err)
		}

		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			log.Fatalf("getSigninToken returned non-200 status: %d", resp.StatusCode)
		}

		var signinTokenResp struct {
			SigninToken string `json:"SigninToken"`
		}

		if err = json.Unmarshal([]byte(body), &signinTokenResp); err != nil {
			log.Fatalf("parse signinTokenResp err: %s", err)
		}

		destination := "https://console.aws.amazon.com/"

		loginURL := fmt.Sprintf(
			"%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
			loginURLPrefix,
			url.QueryEscape(destination),
			url.QueryEscape(signinTokenResp.SigninToken),
		)

		ok := browser.Open(loginURL, nil)
		if !ok {
			log.Printf("browser open failed")
			fmt.Println("Login url:")
			fmt.Println(loginURL)
		}
	} else {
		env := environ(os.Environ())
		env.Set("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
		env.Set("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
		env.Set("AWS_SESSION_TOKEN", *creds.SessionToken)
		env.Set("AWS_REGION", creds.Region)
		env.Set("AWSSO_PROFILE", name)
		env.Set("AWSSO_SESSION_EXPIRATION", strconv.Itoa(int(creds.Expiration.Unix())))

		var cmd *exec.Cmd
		if execCmd != "" {
			cmd = exec.Command("/bin/sh", "-c", execCmd)
		} else {
			shell := os.Getenv("SHELL")
			if shell == "" {
				shell = "/usr/bin/env bash"
			}
			cmd = exec.Command(shell)
		}
		cmd.Env = env
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		sigs := make(chan os.Signal, 1)

		signal.Notify(sigs, os.Interrupt, os.Kill)

		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- cmd.Wait()
			close(waitCh)
		}()

		for {
			select {
			case sig := <-sigs:
				if err := cmd.Process.Signal(sig); err != nil {
					log.Fatal(err)
					break
				}
			case err := <-waitCh:
				var waitStatus syscall.WaitStatus
				if exitError, ok := err.(*exec.ExitError); ok {
					waitStatus = exitError.Sys().(syscall.WaitStatus)
					os.Exit(waitStatus.ExitStatus())
				}
				if err != nil {
					log.Fatal(err)
				}
				return
			}
		}
	}
}

func credentialHelperCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credential-helper",
		Short: "credential-helper for aws cli",
		Run:   credentialHelperAction,
	}

	cmd.Flags().StringVarP(&accountIDF, "account-id", "", "", "Account ID")
	cmd.Flags().StringVarP(&roleNameF, "role", "", "", "Role Name")
	cmd.Flags().StringVarP(&accountNameF, "name", "", "", "Account Name (friendly)")
	cmd.Flags().IntVarP(&timeoutMinutesSession, "timeout-minutes", "", 30, "Session Timeout in minutes")

	cmd.ValidArgsFunction = sessionCompletions

	return cmd
}

func credentialHelperAction(cmd *cobra.Command, args []string) {
	var (
		accountID   string
		roleName    string
		accountName string
	)

	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	if accountIDF != "" && roleNameF != "" {
		accountID = accountIDF
		roleName = roleNameF
		accountName = accountNameF
	} else {
		log.Fatalf("usage: session --account-id <id> --role <role> [--name <friendly-name>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	userPresenceBypassToken := os.Getenv("AWSSO_TOKEN")
	creds, err := client.Session(profileID, accountID, roleName, accountName, userPresenceBypassToken)
	if err != nil {
		log.Fatal(err)
	}

	if accountName == "" {
		accountName = fmt.Sprintf("%s-%s", accountID, roleName)
	}

	// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
	credHelperResult := struct {
		Version         int    `json:"Version"`
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Expiration      string `json:"Expiration"`
	}{
		Version:         1,
		AccessKeyId:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
		Expiration:      creds.Expiration.Format(time.RFC3339),
	}

	out, err := json.Marshal(credHelperResult)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}

type environ []string

func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}

func listAccountsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-accounts",
		Short: "list accounts+roles",
		Run:   listAccountsAction,
	}

	rootCmd.PersistentFlags().BoolVarP(&csvF, "csv", "", false, "Output as csv")

	return cmd
}

func listAccountsAction(cmd *cobra.Command, args []string) {
	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	accts, err := client.ListAccountsRoles(profileID)
	if err != nil {
		log.Fatal(err)
	}

	var cacheF *os.File
	acctCachePath := config.AccountCachePath(profileID)
	if acctCachePath != "" {
		cacheF, err = os.Create(acctCachePath)
		if err == nil {
			defer cacheF.Close()
		}
	}

	cacheW := csv.NewWriter(cacheF)
	defer cacheW.Flush()

	csvStd := csv.NewWriter(os.Stdout)
	defer csvStd.Flush()

	for _, acct := range accts.Accounts {
		if csvF {
			csvStd.Write([]string{acct.AccountName, acct.AccountID, acct.RoleName, acct.AccountEmail})
		} else {
			fmt.Printf("%s %s %s %s\n", acct.AccountName, acct.AccountID, acct.RoleName, acct.AccountEmail)
		}
		if cacheF != nil {
			cacheW.Write([]string{acct.AccountName, acct.AccountID, acct.RoleName, acct.AccountEmail})
		}
	}
}

func listProfilesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-profiles",
		Short: "list profiles",
		Run:   listProfilesAction,
	}

	return cmd
}

func listProfilesAction(cmd *cobra.Command, args []string) {
	client := client.NewClient()
	err := client.Ping()
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}
	profiles, err := client.ListProfiles()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range profiles.Profiles {
		fmt.Printf("%15.15s %15.15s %s\n", p.ID, p.Region, p.StartUrl)
	}
}

func tokenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "create a user presence token",
		Run:   tokenAction,
	}

	cmd.Flags().IntVarP(&timeoutMinutesSession, "timeout-minutes", "", 10, "Token timeout in minutes")

	return cmd
}

func tokenAction(c *cobra.Command, args []string) {
	client := client.NewClient()
	token, err := client.GetUserPresenceBypassToken(profileID, timeoutMinutesSession)
	if err != nil {
		log.Fatalf("Server communication error: %s", err)
	}

	env := environ(os.Environ())
	env.Set("AWSSO_TOKEN", token.Token)

	var cmd *exec.Cmd
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/usr/bin/env bash"
	}
	cmd = exec.Command(shell)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, os.Interrupt, os.Kill)

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	for {
		select {
		case sig := <-sigs:
			if err := cmd.Process.Signal(sig); err != nil {
				log.Fatal(err)
				break
			}
		case err := <-waitCh:
			var waitStatus syscall.WaitStatus
			if exitError, ok := err.(*exec.ExitError); ok {
				waitStatus = exitError.Sys().(syscall.WaitStatus)
				os.Exit(waitStatus.ExitStatus())
			}
			if err != nil {
				log.Fatal(err)
			}
			return
		}
	}
}

func fidoRegisterCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "fido-register",
		Short: "register a fido device",
		Run:   fidoRegisterAction,
	}
}

func fidoRegisterAction(cmd *cobra.Command, args []string) {
	handle, err := u2f.RegisterDevice()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key-handle:\n%s\n", handle.MarshalKey())
}
