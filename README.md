# awsso-agent

`awsso` is a credential agent for AWS SSO (AWS IAM Identity Center) credentials. You can think of it like "an ssh-agent but for AWS SSO credentials".

The SSO token is cached only in memory (not on disk). The agent will use that token to provide the requested sts credentials (after authenticating).

## Building

Run `make` to build the `awsso` binary.

## Usage

Start the agent process by running.
```
$ awsso server
```

Login to allow the agent to fetch an auth token. This command will open a browser window and wait for you to login and authorize the request:

```
$ awsso login
2022/10/15 14:27:14 ok
```

List available accounts:

```
$ awsso list-accounts
example-dev 153646406880 ReadOnlyAccess dev-email@example.com
example-dev 153646406880 AdministratorAccess dev-email@example.com
example-prod 298944583592 ReadOnlyAccess prod-email@example.com
example-prod 298944583592 AdministratorAccess prod-email@example.com
```

Get session credentials for an account (auto sets the credentials in your shell):

```
$ awsso session example-dev-153646406880-ReadOnlyAccess
# tmp aws creds are now set in the current shell
$ aws sts get-caller-identity
{
    "UserId": "AROATB4H2GQUZM6VC3PNJ:example-user",
    "Account": "153646406880",
    "Arn": "arn:aws:sts::153646406880:assumed-role/AWSReservedSSO_ReadOnlyAccess_ecc6256a681083fc/example-user"
}
```

The above command will tab complete if you install tab completions in your shell (see `awsso completion -h`). For bash you can add the following to your ~/.bashrc:

```
if which awsso &>/dev/null ; then
  . <(awsso completion bash)
fi
```

## User presence verification

By default `awsso` will verify a user is present before issuing session credentials. Currently the only supported method of doing this is with a FIDO or FIDO2 device. This gives some protection from a rouge application minting credentials without you knowing about it. It also allows for forwarding the awsso agent's socket over ssh without worrying about the normal issues with agent forwarding abuse.

You need to register and configure 1 or more FIDO keys. To add a key, get a key handle by running the command:
```
$ awsso fido-register
2022/10/15 14:45:37 registering device, tap key to continue
key-handle:
eyJQdWJsaWNLZXlCeXRlcyI6IkJBL0hqcjJRcTkwQzVzOVBWU2laTEIvVWUrT080bWZhbWo1Ym5xczF4U3B4NGM4V2IxVGROaE4yZWhnRk8rZUdCNDRkZ1ZiRG54RjdKZ2ZTNFl6cGVTYz0iLCJLZXlIYW5kbGVCeXRlcyI6IjZCRVg5VTVyZDErV3k1bHBwYXNGSXNnVFZaa0tqeDd1ME1nMWFrbDRXaERvcTNBWmw1Q0puVzQwRDEwejZ5TThSOGRIckRxSkpCU2JaeXNNVWdXdS9nPT0iLCJBdHRlc3RhdGlvbkNlcnRCeXRlcyI6bnVsbCwiU2lnbmF0dXJlQnl0ZXMiOm51bGx9
```

Add this keyhandle to the `fido-key-handles` list in the config file.

It is possible to run the `awsso` agent without requiring user presence verification. To do that set `allow-no-user-verify=false` in the config and don't set any `fido-key-handles`. Running in this configuration is not recommended.

## Configuration

`awsso` uses a config file located at `$XDG_CONFIG_HOME/awsso/awsso.toml` or `$HOME/Library/Application Support/awsso/awsso.toml` on darwin.

Here's an example config file:
```
fido-key-handles = [
# from the output of `awsso fido-register`
"eyJQdWJsaWNLZXlCeXRlcyI6IkJIU0lQdnVCSi9vR3ZORzE0eHA0OEs0WmRTM2FpZ29veHg1WVZDT0JHS0NTUzRQTkRWeFBqYlJwbmxPZ2JTK1Nna2svUVY1ZERJTzFYTzZIVWhxMmc4bz0iLCJLZXlIYW5kbGVCeXRlcyI6InFTdnVRelBXcmE0NjV1NGJRaUpVa1NkMkl3dnhjVEJaYm1rK2hvU1BQWUVkSDVWbGJBNHVmR0VJUlVLQVBNUXUyb1JSVHNLaGxmWUl1KzRQU2ltYTVnPT0iLCJBdHRlc3RhdGlvbkNlcnRCeXRlcyI6bnVsbCwiU2lnbmF0dXJlQnl0ZXMiOm51bGx9"
]

[[profile]]
id = "default"
start-url = "https://d-263deadbeef.awsapps.com/start"
account-id = "153646406880"
```

## Running the agent as a daemon

On linux, the recommended way of running the agent is with a systemd user unit. An example unit file:
```
[Unit]
Description=AWSSO agent server

[Service]
ExecStart=/some/path/to/awsso server

[Install]
WantedBy=default.target
```

Adjust the `ExecStart` path and then install this in `~/.config/systemd/user/awsso-server.service`.
Run `systemctl --user enable awsso-server` to enable the service.
