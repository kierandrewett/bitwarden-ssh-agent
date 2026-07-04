# bitwarden-ssh-agent

A headless SSH agent daemon that sources your SSH private keys from your
**Bitwarden vault** instead of loose files on disk.

If you reinstall your laptop or hop between machines, your SSH keys come with
you: store them once as Bitwarden **SSH Key** items and this agent serves them
over the standard SSH agent protocol. It is designed to run as a
`systemd --user` service — no GUI required (unlike Bitwarden's built-in desktop
agent).

## Security model

- Private keys are fetched from the vault, parsed, and held only in this
  process's memory — never written to disk in plaintext.
- Signing happens in-process (RustCrypto). The daemon speaks the SSH agent
  protocol on a Unix socket, so agent-forwarding works transparently.
- The socket lives at `$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock`, created
  `0600`. A stale socket from a previous run is removed on startup.
- Secrets in flight (master password, `BW_SESSION`, API secret) are wrapped in
  `secrecy`/`zeroize` and passed to the `bw` subprocess through its own
  environment — never process-wide env, never on the command line, never
  logged.
- The master password is never stored in any config file — it's provided
  either as a systemd credential or typed on demand (see below). The config
  file holds only the Bitwarden API key (device auth), and the daemon refuses
  to read it if its permissions are looser than `0600`.
- RSA signatures use the client's requested algorithm (`rsa-sha2-256` /
  `rsa-sha2-512`); the deprecated SHA-1 `ssh-rsa` is never used.

## How it works

Bitwarden has no usable Rust SDK for the personal vault, so this daemon shells
out to the official **`bw` CLI** to read items. Authentication has two steps:

1. **Device auth** with your personal **API key** (`bw login --apikey`). This
   only authenticates the device — the vault is still *locked* afterward.
2. **Unlock** with your **master password** (`bw unlock`), which yields a session
   key that decrypts items. There is no way around needing the master password
   at unlock time.

Once unlocked, all SSH Key items are parsed and cached in memory for the
daemon's lifetime.

## Prerequisites

- **Rust** (to build) — <https://rustup.rs>.
- The **Bitwarden CLI** (`bw`), which needs Node.js:
  ```sh
  npm install -g @bitwarden/cli
  ```
  Make sure `bw` is on your `PATH`. (You can override the binary location with
  the `BW_CLI_PATH` environment variable.)
- **systemd** (for the service and the `systemd-ask-password` prompt).
- One or more Bitwarden items of type **SSH Key** in your vault (Bitwarden can
  generate Ed25519 keys, or you can import existing RSA/ECDSA/Ed25519 keys).

## Create a Bitwarden API key

1. Log in to the Bitwarden web vault.
2. Go to **Account settings → Security → Keys**.
3. Under **API key**, click **View API Key**.
4. Copy the `client_id` (`user.…`) and `client_secret`.

This API key only authenticates the device; it cannot unlock the vault on its
own.

## Build & install

```sh
git clone https://github.com/kierandrewett/bitwarden-ssh-agent
cd bitwarden-ssh-agent
cargo install --path .        # installs to ~/.cargo/bin/bitwarden-ssh-agent
```

(If you prefer a system location, `cargo build --release` and copy
`target/release/bitwarden-ssh-agent` to `/usr/local/bin`, then adjust
`ExecStart=` in the unit file.)

## Quick start: `bitwarden-ssh-agent setup` (recommended)

Once the binary is built, one command does everything the manual sections
below describe — no hand-editing of config or unit files:

```sh
bitwarden-ssh-agent setup
```

It walks you through, prompting at each step (and asking before overwriting
anything, so it is safe to re-run):

1. **Checks for the `bw` CLI** and offers to `npm install -g @bitwarden/cli`
   it for you if it's missing (it won't run a global npm install without
   asking first).
2. **Collects your Bitwarden API key** (`client_id` / `client_secret`, plus an
   optional self-hosted server URL) and **validates it** by actually running
   `bw login --apikey` before writing anything.
3. **Writes `~/.config/bitwarden-ssh-agent/config.toml`** with `0600`
   permissions.
4. **Sets up the master-password unlock strategy** — either auto-unlock via an
   encrypted systemd credential (it prompts for the password with masked input,
   verifies it unlocks the vault, then pipes it straight into
   `systemd-creds encrypt`; the plaintext never touches disk or your shell
   history), or on-demand prompting via `systemd-ask-password`.
5. **Installs the `systemd --user` unit** with `ExecStart=` pointing at the
   binary you just built.
6. **Enables and starts** the service and checks it came up.
7. **Prints the `SSH_AUTH_SOCK` line** to add to your shell rc.

The remaining sections document the same steps done by hand, for anyone who
wants to see exactly what `setup` automates, doesn't use systemd, or prefers to
manage the pieces themselves.

## Manual setup

### Configure the API key

Create `~/.config/bitwarden-ssh-agent/config.toml` from the example:

```sh
mkdir -p ~/.config/bitwarden-ssh-agent
cp config.example.toml ~/.config/bitwarden-ssh-agent/config.toml
chmod 600 ~/.config/bitwarden-ssh-agent/config.toml
$EDITOR ~/.config/bitwarden-ssh-agent/config.toml
```

Alternatively, set `BW_CLIENTID` / `BW_CLIENTSECRET` in the environment (e.g. a
systemd `EnvironmentFile=`, `chmod 600`). Environment variables take precedence
over the config file. **Do not put your master password here.**

### Install the systemd user service

```sh
mkdir -p ~/.config/systemd/user
cp packaging/bitwarden-ssh-agent.service ~/.config/systemd/user/
# (edit the copy if bw/node live somewhere other than ~/.npm-global/bin)
systemctl --user daemon-reload
systemctl --user enable --now bitwarden-ssh-agent.service
systemctl --user status bitwarden-ssh-agent.service
journalctl --user -u bitwarden-ssh-agent.service -f
```

### Supplying the master password

There are two ways; pick one.

#### A) Auto-unlock at startup with a systemd credential (recommended)

Encrypt the master password once (systemd stores an opaque, host-bound blob —
not the plaintext):

```sh
systemd-creds encrypt --name=bw_master_password - \
    ~/.config/bitwarden-ssh-agent/bw_master_password.cred
# type your master password, then press Ctrl-D
chmod 600 ~/.config/bitwarden-ssh-agent/bw_master_password.cred
```

Then uncomment this line in the unit file and reload:

```ini
LoadCredentialEncrypted=bw_master_password:%h/.config/bitwarden-ssh-agent/bw_master_password.cred
```

The daemon reads it from `$CREDENTIALS_DIRECTORY/bw_master_password` and unlocks
the vault immediately at startup.

#### B) On-demand prompt (no credential provisioned)

If you provision no credential, the daemon still starts — in a **locked** state.
The **first** time an SSH client actually uses the agent, it prompts for the
master password via `systemd-ask-password` (which handles TTY / SSH askpass /
plymouth). It unlocks, caches your keys, and completes the request. If several
SSH connections race in during the locked window, only **one** prompt fires and
the rest wait on it.

Once unlocked (either way), the daemon stays unlocked in memory for its
lifetime — this is a personal single-user machine daemon, so there is no re-lock
timer.

### Point SSH at the agent

The socket path is fixed and predictable, so just export it (e.g. in your shell
rc):

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/bitwarden-ssh-agent.sock"
```

Then use SSH normally:

```sh
ssh-add -l          # list the keys the agent is serving
ssh you@server      # authenticates via the agent; forwarding works
```

## Configuration reference

Config file (`~/.config/bitwarden-ssh-agent/config.toml`, `0600`):

| Key             | Env override      | Purpose                                   |
| --------------- | ----------------- | ----------------------------------------- |
| `client_id`     | `BW_CLIENTID`     | Bitwarden API key client id (`user.…`)    |
| `client_secret` | `BW_CLIENTSECRET` | Bitwarden API key secret                  |
| `server`        | `BW_SERVER`       | Self-hosted server URL (optional)         |

Other environment variables:

| Variable      | Purpose                                             |
| ------------- | --------------------------------------------------- |
| `BW_CLI_PATH` | Full path to the `bw` binary if not on `PATH`       |
| `RUST_LOG`    | Log level (`info` default; `debug` for more detail) |

## CLI

```
bitwarden-ssh-agent setup [--config <PATH>]
bitwarden-ssh-agent serve [--socket <PATH>] [--config <PATH>]
```

`setup` runs the interactive one-command configuration flow (see
[Quick start](#quick-start-bitwarden-ssh-agent-setup-recommended)). `serve` runs
the daemon and is the default subcommand: `--socket` overrides the socket path
and `--config` overrides the config file location. Run `--help` for details.

## Troubleshooting

- **`Bitwarden CLI check failed … No such file or directory`** — `bw` isn't on
  the service's `PATH`. Fix `Environment=PATH=…` in the unit or set
  `BW_CLI_PATH`.
- **`bw unlock failed (wrong master password?)`** — the supplied master password
  was rejected.
- **`vault unlocked but contains no usable SSH Key items`** — add an item of
  type *SSH Key* in Bitwarden.
- Watch logs with `journalctl --user -u bitwarden-ssh-agent.service -f`.
