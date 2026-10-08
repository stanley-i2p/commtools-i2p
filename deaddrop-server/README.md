# DeadDrop Server

This independent Rust workspace contains the DeadDrop server used by
CommTools-I2P clients for replicated offline message storage and retrieval.

The server is intentionally content-agnostic. It stores opaque encrypted blobs
and does not participate in client identity, message encryption, or message
decryption.

## Project Layout

```text
deaddrop-server/
|-- Cargo.lock
|-- Cargo.toml
|-- README.md
`-- src/
    `-- main.rs
```

Official release binaries are currently provided for Linux x86_64 GNU only.

## Requirements

```bash
sudo apt install build-essential curl -y
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Use the default installation option when prompted, then load the Rust
environment:

```bash
source "$HOME/.cargo/env"
```

An I2P router with SAM enabled is required. The default SAM endpoint used by
the server is `127.0.0.1:7656`.

## Build

Run this command from the `deaddrop-server` directory:

```bash
cargo build --release
```

The resulting binary is written to:

```text
target/release/deaddrop-server
```

## Run

```bash
./target/release/deaddrop-server
```

The default configuration connects to SAM at `127.0.0.1:7656` and hosts one
persistent drop identity. Available command-line options are:

```text
Usage: deaddrop-server [OPTIONS]

Options:
  --sam <HOST:PORT>  SAM endpoint [default: 127.0.0.1:7656]
  --drops <COUNT>    Persistent drop identities to host [default: 1; max: 16]
  -h, --help         Show help
  -V, --version      Show version
```

For example:

```bash
./target/release/deaddrop-server --sam 127.0.0.1:7656 --drops 1
```

One server process can host multiple persistent drop identities, but drops on
the same machine and I2P router share a common failure domain. For meaningful
replication diversity, running one drop on each independently operated server
is recommended.

Earlier server builds started three identities by default. To continue serving
all three existing `drop_0`, `drop_1`, and `drop_2` destinations, start the
updated server with:

```bash
./target/release/deaddrop-server --drops 3
```

Using a lower count does not delete identities or blobs above that count; those
drops are simply not served during that run.

## Data Directory

The server stores its persistent SAM identities and opaque queued blobs under:

```text
~/.deaddrop-server/
|-- identities/
|   |-- drop_0.dat
|   `-- ...
`-- storage/
    |-- drop_0/
    `-- ...
```

Preserve the complete data directory across restarts to retain the same I2P
destinations and queued blobs.

## Migrating From `.termchat-server`

Older releases used `.termchat-server` as the data directory. The directory can
be renamed without changing the persistent B32 addresses or stored blobs.

Before migrating:

1. Stop the old server completely.
2. Confirm that no server process is still running.
3. Confirm that `.deaddrop-server` does not already exist.

On Linux or macOS, run:

```bash
mv "$HOME/.termchat-server" "$HOME/.deaddrop-server"
```

Start the updated server only after the rename completes. Move the entire
directory as one unit; do not move only `identities` or only `storage`.
