# CommTools-I2P

This repository contains the CommTools core libraries and two applications built on top of them:

- **TermComm-I2P** - terminal client
- **DeskComm-I2P** - Slint desktop client

## Build TermComm-I2P

From the repository root:

```bash
cargo build --release -p termcomm-i2p
```

The executable will be created at `target/release/termcomm-i2p`.

[TermComm-I2P screenshot](screenshots/termcomm-i2p.png)

Run the built application:

```bash
./target/release/termcomm-i2p
```

Alternatively, build and run it through Cargo:

```bash
cargo run --release -p termcomm-i2p
```

TermComm-I2P uses `~/.termcomm-i2p` by default. To use a different, independent vault directory:

```bash
./target/release/termcomm-i2p --data-dir /path/to/vault
```

Available options:

```text
--data-dir PATH  Use an independent application vault
-h, --help       Print help
-V, --version    Print version
```

## Build DeskComm-I2P

From the repository root:

```bash
cargo build --release -p deskcomm-i2p
```

The executable will be created at `target/release/deskcomm-i2p`.

[DeskComm-I2P screenshot](screenshots/deskcomm-i2p.png)

Run the built application:

```bash
./target/release/deskcomm-i2p
```

Alternatively, build and run it through Cargo:

```bash
cargo run --release -p deskcomm-i2p
```

DeskComm-I2P uses `~/.deskcomm-i2p` by default. To use a different, independent vault directory:

```bash
./target/release/deskcomm-i2p --data-dir /path/to/vault
```

Available options:

```text
--data-dir PATH  Use an independent application vault
-h, --help       Print help
-V, --version    Print version
```

## Architecture

```text
TermComm-I2P (Ratatui)          DeskComm-I2P (Slint)
          \                           /
           \  commands and events   /
            v                       v
              commtools-runtime
       async lifecycle and orchestration
                       |
                       v
                commtools-core
       protocol, security, sessions, SAM,
             vault and storage logic
                       |
                       v
             I2P router and deaddrops
```

`commtools-core` contains the presentation-independent communication and security logic.
`commtools-runtime` exposes that logic through typed commands, snapshots, and events. Each UI can
therefore present a different interface while using the same underlying behavior and validation.
