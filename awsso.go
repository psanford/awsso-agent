package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	timeoutMinutesSession int
	accountIDF            string
	roleNameF             string
	accountNameF          string

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
	rootCmd.AddCommand(listAccountsCommand())

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
		log.Fatalf("usage: assume <account_id|long-account-id> [--account-id <id>, --role <role>, --name <friendly-name>]")
	}

	if accountID == "" || roleName == "" {
		log.Fatalf("Invalid account")
	}

	creds, err := client.Session(profileID, accountID, roleName, accountName)
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
	} else {
		env := environ(os.Environ())
		env.Set("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
		env.Set("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
		env.Set("AWS_SESSION_TOKEN", *creds.SessionToken)
		env.Set("AWS_DEFAULT_REGION", creds.Region)
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

	for _, acct := range accts.Accounts {
		fmt.Printf("%s %s %s %s\n", acct.AccountName, acct.AccountID, acct.RoleName, acct.AccountEmail)
		if cacheF != nil {
			fmt.Fprintf(cacheF, "%s %s %s %s\n", acct.AccountName, acct.AccountID, acct.RoleName, acct.AccountEmail)
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
