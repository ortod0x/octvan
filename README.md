# Octra Vanity Wallet Generator

A fast C++ vanity wallet generator for Octra addresses.

The tool generates random 12-word BIP39 mnemonics, derives an Octra wallet seed, creates an Ed25519 keypair, derives the Octra address, and searches until the address matches your requested pattern.

It can print wallets as JSON, save wallet JSON files, and store generated vanity wallets in SQLite.

## Important Safety Notes

This tool prints private keys, seed hex values, and mnemonic phrases. Anyone with any of those values can control the wallet.

- Run this only on a machine you trust.
- Do not paste generated mnemonics or private keys into chats, logs, screenshots, or issue reports.
- Do not commit generated wallet files, SQLite databases, or terminal output containing secrets.
- For real funds, prefer generating keys offline and backing them up securely.
- Vanity generation is random. Harder patterns can take a very long time.

## Disclaimer

This software is provided for educational and experimental use only. The author and contributors are not responsible for lost funds, leaked private keys, compromised mnemonics, insecure devices, malware, user mistakes, misuse of this tool, or any cybersecurity incident that may result from using it.

You are responsible for reviewing the code, understanding the risks, securing your environment, protecting generated secrets, and complying with any laws or rules that apply to your use of this software. Use at your own risk.

## Features

- Prefix, suffix, and contains matching
- Case-insensitive matching by default
- Optional case-sensitive matching
- Multi-threaded generation
- Generate one or many matched wallets with `--max`
- Optional maximum attempt cap with `--max-tries`
- JSON output for scripting
- Optional wallet JSON output file
- Optional SQLite storage

## Requirements

- C++20 compiler, tested with `g++`
- OpenSSL development headers/libraries
- SQLite3 development headers/libraries

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y g++ openssl libssl-dev sqlite3 libsqlite3-dev
```

## Build

Use the included build script:

```bash
chmod +x build.sh
./build.sh
```

Or compile directly:

```bash
g++ -std=c++20 -O3 -march=native ./octra_vanity_wallet.cpp \
  -o ./octra_vanity \
  -lssl -lcrypto -lsqlite3
```

## Quick Start

Generate one wallet:

```bash
./octra_vanity
```

Generate an address with a prefix:

```bash
./octra_vanity --prefix abc
```

`--prefix abc` automatically searches for addresses starting with `octabc`.

Generate two matched wallets:

```bash
./octra_vanity --prefix abc --max 2
```

Generate a wallet with a suffix:

```bash
./octra_vanity --suffix xyz
```

Generate a wallet containing text anywhere after `oct`:

```bash
./octra_vanity --contains cafe
```

Use all CPU threads automatically:

```bash
./octra_vanity --prefix cool
```

Set thread count manually:

```bash
./octra_vanity --prefix cool --threads 8
```

## CLI Options

```text
--prefix P          Match addresses starting with P. If P does not start with oct, oct is added.
--suffix S          Match addresses ending with S.
--contains X        Match addresses containing X.
--case-sensitive    Match exact case. Default is case-insensitive.
--max N             Stop after N matched wallets. Default: 1.
--max-tries N       Stop after N generated attempts if not enough matches are found.
--progress N        Print progress every N generated attempts. Default: 100000.
--threads N         Number of worker threads. Default: hardware concurrency.
--out FILE          Write generated wallet JSON to FILE.
--db FILE           Save generated wallet(s) to a SQLite database.
--rpc URL           RPC URL written into wallet JSON files. Default: https://octra.network/rpc
--force             Overwrite existing --out file.
--quiet             Compact JSON output and suppress progress logs.
--benchmark         Generate wallets without matching.
--help              Show usage.
```

## Output Fields

For one matched wallet, output looks like this:

```json
{
  "address": "oct...",
  "priv": "base64-private-seed",
  "pub": "base64-public-key",
  "seed_hex": "64-character-private-seed-hex",
  "mnemonic": "twelve word mnemonic phrase appears here",
  "attempts": 4,
  "threads": 16,
  "matched": true,
  "elapsed_seconds": 0.051
}
```

Field meanings:

- `address`: The Octra wallet address.
- `priv`: Base64-encoded 32-byte private seed used by the wallet.
- `pub`: Base64-encoded Ed25519 public key.
- `seed_hex`: Same private seed as `priv`, encoded as lowercase hex.
- `mnemonic`: The 12-word mnemonic used to derive the wallet seed.
- `attempts`: Generated candidate count when this wallet was found.
- `threads`: Worker thread count used by the run.
- `matched`: Whether the generated wallet matched the requested pattern.
- `elapsed_seconds`: Runtime in seconds.

For multiple matches, output uses a `wallets` array:

```json
{
  "matched": 2,
  "attempts": 17,
  "threads": 16,
  "elapsed_seconds": 0.051,
  "wallets": [
    {
      "address": "oct...",
      "priv": "base64-private-seed",
      "pub": "base64-public-key",
      "seed_hex": "64-character-private-seed-hex",
      "mnemonic": "twelve word mnemonic phrase appears here",
      "attempts": 1
    }
  ]
}
```

## Getting the Public Key, Private Key, and Mnemonic

Run:

```bash
./octra_vanity --prefix abc
```

The values are printed in JSON:

- Public key: copy the `pub` field.
- Private key: copy the `priv` field.
- Private seed hex: copy the `seed_hex` field.
- Mnemonic phrase: copy the `mnemonic` field.
- Address: copy the `address` field.

Example with compact output:

```bash
./octra_vanity --quiet --prefix abc
```

You can pipe the output into `jq` if installed:

```bash
./octra_vanity --quiet --prefix abc | jq -r '.address'
./octra_vanity --quiet --prefix abc | jq -r '.pub'
./octra_vanity --quiet --prefix abc | jq -r '.priv'
./octra_vanity --quiet --prefix abc | jq -r '.seed_hex'
./octra_vanity --quiet --prefix abc | jq -r '.mnemonic'
```

For multiple wallets:

```bash
./octra_vanity --quiet --prefix abc --max 2 | jq -r '.wallets[].address'
./octra_vanity --quiet --prefix abc --max 2 | jq -r '.wallets[].pub'
./octra_vanity --quiet --prefix abc --max 2 | jq -r '.wallets[].priv'
./octra_vanity --quiet --prefix abc --max 2 | jq -r '.wallets[].mnemonic'
```

## Save Wallet JSON

Save one generated wallet:

```bash
./octra_vanity --prefix abc --out wallet.json
```

Overwrite an existing file:

```bash
./octra_vanity --prefix abc --out wallet.json --force
```

The wallet file contains:

```json
{
  "priv": "base64-private-seed",
  "addr": "oct-address",
  "rpc": "https://octra.network/rpc"
}
```

Set a custom RPC URL:

```bash
./octra_vanity --prefix abc --out wallet.json --rpc https://example.com/rpc
```

For `--max N` where `N > 1`, the output file contains a `wallets` array.

## Save to SQLite

Save generated wallet(s) into a SQLite database:

```bash
./octra_vanity --prefix abc --db vanity.sqlite3
```

The tool creates a `vanity_wallets` table:

```sql
CREATE TABLE IF NOT EXISTS vanity_wallets (
  address TEXT PRIMARY KEY,
  private_key TEXT NOT NULL,
  mnemonic TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
```

Query saved wallets:

```bash
sqlite3 vanity.sqlite3 'SELECT address, private_key, mnemonic, created_at FROM vanity_wallets;'
```

Do not publish this database if it contains real wallets.

## Matching Rules

Octra addresses start with `oct`.

Prefix matching:

```bash
./octra_vanity --prefix dog
```

This searches for:

```text
octdog...
```

Suffix matching:

```bash
./octra_vanity --suffix 777
```

Contains matching:

```bash
./octra_vanity --contains cafe
```

Combined matching:

```bash
./octra_vanity --prefix ab --contains cafe --suffix 7
```

Case-sensitive matching:

```bash
./octra_vanity --prefix AbC --case-sensitive
```

Only Base58 characters are accepted in patterns. Invalid characters such as `0`, `O`, `I`, and `l` are rejected.

## Performance Notes

Search time grows quickly as the pattern gets longer or more specific.

Approximate intuition:

- 1 Base58 character: about 58 attempts
- 2 Base58 characters: about 3,364 attempts
- 3 Base58 characters: about 195,112 attempts
- 4 Base58 characters: about 11.3 million attempts

Case-insensitive search can be easier for letter-heavy patterns because uppercase and lowercase both match.

Use progress logs:

```bash
./octra_vanity --prefix cool --progress 10000
```

Use a hard attempt cap:

```bash
./octra_vanity --prefix cool --max-tries 1000000
```

Run a benchmark:

```bash
./octra_vanity --benchmark --max-tries 1000000
```

Beer donations:

```
oct11111mb5DKaFzHDsWqGxvEegLmea4epKmD5UwK8H3PJs
```
