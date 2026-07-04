# bitwarden-ssh-agent

A headless SSH agent that serves keys stored as Bitwarden **SSH Key** vault
items over the standard ssh-agent protocol. Runs as a `systemd --user`
service, no GUI required.

## How it works

Shells out to the `bw` CLI (no usable Rust SDK exists). Two-step auth:

1. `bw login --apikey` — device auth via your Bitwarden API key. Vault stays locked.
2. `bw unlock` — master password, yields a session key. No way around this.

Once unlocked, SSH Key items are parsed and cached in memory for the daemon's
lifetime (no re-lock timer — single-user machine daemon).

## Security model

- Keys are held only in process memory, never written to disk in plaintext.
- Signing happens in-process (RustCrypto) over a Unix socket
  (`$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock`, `0600`; stale sockets removed
  on startup).
- Master password / `BW_SESSION` / API secret are wrapped in
  `secrecy`/`zeroize`, passed to `bw` via its own env — never process-wide
  env, command line, or logs.
- Master password is never stored in config. Config holds only the API key,
  and is rejected if permissions are looser than `0600`.
- RSA signing uses `rsa-sha2-256`/`512`, never the deprecated `ssh-rsa` (SHA-1).

## Prerequisites

- Rust (to build) — <https://rustup.rs>
- Bitwarden CLI: `npm install -g @bitwarden/cli` (on `PATH`, or set `BW_CLI_PATH`)
- systemd (service + `systemd-ask-password`)
- At least one Bitwarden item of type **SSH Key**

## Build & install

```sh
git clone https://github.com/kierandrewett/bitwarden-ssh-agent
cd bitwarden-ssh-agent
cargo install --path .        # -> ~/.cargo/bin/bitwarden-ssh-agent
```

## Setup

```sh
bitwarden-ssh-agent setup
```

Interactive, idempotent (asks before overwriting). Handles all of:

1. Installs `bw` if missing (asks first).
2. Prompts for your Bitwarden API key (`client_id`/`client_secret` + optional
   server URL), validates with `bw login --apikey`.
3. Writes `~/.config/bitwarden-ssh-agent/config.toml` (`0600`).
4. Asks whether to set up auto-unlock at startup (provisions an encrypted
   systemd credential; plaintext never touches disk/history). Either way,
   `bitwarden-ssh-agent unlock` unlocks a running daemon on demand.
5. Installs and enables the `systemd --user` unit.
6. Prints the `SSH_AUTH_SOCK` line to add to your shell rc.

Get the API key for step 2 from the web vault: **Account settings → Security
→ Keys → View API Key**.

The [Manual setup](#manual-setup) section below covers the same steps by hand.

## Import existing keys

Bring keys already in `~/.ssh` (e.g. `id_ed25519`) into the vault:

```sh
bitwarden-ssh-agent import          # --dry-run to preview, --ssh-dir <PATH> for a different dir
```

1. Scans `~/.ssh` for OpenSSH private keys, showing algorithm, fingerprint,
   passphrase status, and whether each is already in the vault.
2. Unlocks its own `bw` session (prompts for master password).
3. Multi-select which keys to import. Per key: skip/overwrite if already
   present; if passphrase-protected, choose decrypt now / store encrypted
   blob (backup only) / skip; set the item name.
4. Creates vault items via `bw` (key piped through stdin, never argv).
5. If the daemon is running, offers to refresh it over its local control
   socket (the same channel `unlock` uses) so the new keys are served
   immediately — no restart, no signal. Run it any time with:
   `bitwarden-ssh-agent refresh`.

## Manual setup

### API key config

```sh
mkdir -p ~/.config/bitwarden-ssh-agent
cp config.example.toml ~/.config/bitwarden-ssh-agent/config.toml
chmod 600 ~/.config/bitwarden-ssh-agent/config.toml
$EDITOR ~/.config/bitwarden-ssh-agent/config.toml
```

Or set `BW_CLIENTID`/`BW_CLIENTSECRET` in the environment (takes precedence
over the config file). Never put the master password here.

### systemd user service

```sh
mkdir -p ~/.config/systemd/user
cp packaging/bitwarden-ssh-agent.service ~/.config/systemd/user/
# edit if bw/node aren't on ~/.npm-global/bin
systemctl --user daemon-reload
systemctl --user enable --now bitwarden-ssh-agent.service
journalctl --user -u bitwarden-ssh-agent.service -f
```

### Master password

Unlock a running-but-locked daemon interactively any time:

```sh
bitwarden-ssh-agent unlock
```

Prompts (masked) in your own terminal, hands the password to the daemon over
a control socket (`$XDG_RUNTIME_DIR/bitwarden-ssh-agent.ctl`, `0600`). Safe
to run concurrently with an in-flight SSH request — unlock is single-flight.

**Auto-unlock at startup (recommended)** — provision a systemd credential.
`--user` is required (produces a user-scoped credential a `systemd --user`
service can decrypt; without it you get `Scope mismatch` and the daemon stays
locked):

```sh
systemd-creds encrypt --user --name=bw_master_password - \
    ~/.config/bitwarden-ssh-agent/bw_master_password.cred
# type master password, Ctrl-D
chmod 600 ~/.config/bitwarden-ssh-agent/bw_master_password.cred
```

Uncomment in the unit file and reload:

```ini
LoadCredentialEncrypted=bw_master_password:%h/.config/bitwarden-ssh-agent/bw_master_password.cred
```

**No credential provisioned** — daemon starts locked. Use
`bitwarden-ssh-agent unlock` after reboot. It also makes a best-effort
`systemd-ask-password` attempt on first use, which only succeeds if an
ask-password agent is watching the queue (not the case on a typical headless
service) — it fails fast rather than hanging.

### Point SSH at the agent

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock"
ssh-add -l
ssh you@server
```

## Configuration reference

`~/.config/bitwarden-ssh-agent/config.toml` (`0600`):

| Key             | Env override      | Purpose                                |
| --------------- | ------------------ | --------------------------------------- |
| `client_id`     | `BW_CLIENTID`      | Bitwarden API key client id (`user.…`) |
| `client_secret` | `BW_CLIENTSECRET`  | Bitwarden API key secret               |
| `server`        | `BW_SERVER`        | Self-hosted server URL (optional)      |

| Env var       | Purpose                                       |
| ------------- | ---------------------------------------------- |
| `BW_CLI_PATH` | Path to `bw` binary if not on `PATH`           |
| `RUST_LOG`    | Log level (`info` default, `debug` for more)   |

## CLI

```
bitwarden-ssh-agent setup  [--config <PATH>]
bitwarden-ssh-agent serve  [--socket <PATH>] [--config <PATH>]
bitwarden-ssh-agent unlock  [--control-socket <PATH>]
bitwarden-ssh-agent refresh [--control-socket <PATH>]
bitwarden-ssh-agent list    [--control-socket <PATH>]
bitwarden-ssh-agent import  [--ssh-dir <PATH>] [--config <PATH>] [--dry-run] [--control-socket <PATH>]
```

A subcommand is required; bare invocation prints help. `--help` for details.

## Troubleshooting

- **`Bitwarden CLI check failed … No such file or directory`** — `bw` isn't
  on the service's `PATH`; fix `Environment=PATH=…` or set `BW_CLI_PATH`.
- **`bw unlock failed (wrong master password?)`** — password was rejected.
- **`vault unlocked but contains no usable SSH Key items`** — add an item of
  type SSH Key in Bitwarden.
- Logs: `journalctl --user -u bitwarden-ssh-agent.service -f`
