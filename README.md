## gpg-fingerprint-filter-gpu

Generate an OpenPGP key whose fingerprint matches a prefix filter, a suffix filter, or both.

Get your lucky key. CUDA powered, so fast.

```
$ ./gpg-fingerprint-filter-gpu --help
  gpg-fingerprint-filter-gpu [OPTIONS] <output>

  <output>                    Save the secret key(s) to this folder
  -a, --algorithm <ALGO>      PGP key algorithm [default: rsa]
  -p, --prefix-pattern <PAT>  Fingerprint prefix filter in custom pattern syntax
  -s, --suffix-pattern <PAT>  Fingerprint suffix filter in custom pattern syntax
  -t, --time-offset <N>       Max key timestamp offset [default: 15552000]
  -w, --thread-per-block <N>  CUDA thread number per block [default: 512]
  -j, --gpg-thread <N>        Number of threads to generate keys [default: # of CPUs]
  -b, --base-time <N>         Base key timestamp in UNIX epoch [default: now]
  -m, --batch-mode <Y/N>      Continue to generate keys even if a match is found [default: N]
  -h, --help
```

### Filter Syntax

Each filter uses a small custom pattern language. It is not regex.

Supported syntax:

- Hex literals: `0-9`, `A-F`
- Variable hex digits: other letters like `X`, `Y`, `Z`
- Repetition: `{N}`
- Grouping: `(PATTERN)`
- Alternation: `|`

Semantics:

- Hex literals match themselves.
- Non-hex letters match any hex digit.
- Reusing the same non-hex letter means the same hex digit must appear again.
- `{N}` repeats the previous digit or group.
- `|` separates alternatives within the same prefix or suffix filter.
- Groups cannot be nested.

Examples:

- `DEADBEEF` means the literal hex string `DEADBEEF`
- `X{8}` means 8 identical hex digits
- `(XY){4}` means the same 2-digit hex sequence repeated 4 times
- `1234|ABCD` means either `1234` or `ABCD`

### Examples

Prefix only:

```bash
./gpg-fingerprint-filter-gpu --prefix-pattern 000000 out
```

Suffix only:

```bash
./gpg-fingerprint-filter-gpu --suffix-pattern 000000 out
```

Different prefix and suffix:

```bash
./gpg-fingerprint-filter-gpu --prefix-pattern 1234 --suffix-pattern 5678 out
```

Mirrored ends are now just explicit prefix and suffix filters:

```bash
./gpg-fingerprint-filter-gpu --prefix-pattern 123456 --suffix-pattern 654321 out
```

### Search Timing Estimates

For independent literal prefix and suffix filters, the expected search space is:

```text
16^(prefix_hex_digits + suffix_hex_digits)
```

Expected time is:

```text
16^(prefix_hex_digits + suffix_hex_digits) / hashes_per_second
```

At a measured rate of about `13.8e9 hashes / sec`, the average time for all-zero prefix and suffix searches is roughly:

| Prefix + suffix | Total constrained hex digits | Expected time |
|---|---:|---:|
| `0000...0000` | 8 | `0.31 s` |
| `00000...00000` | 10 | `79.5 s` |
| `000000...000000` | 12 | `5.66 h` |
| `0000000...0000000` | 14 | `90.5 h` |
| `00000000...00000000` | 16 | `1449 h` |

These are averages, not guarantees. A run may finish much earlier or much later.

### Import Key

Import the generated private key:

```bash
$ gpg --allow-non-selfsigned-uid --import private.pgp
```

The private key file doesn't have a self-signed UID on it. GPG will display `NONAME` as the default UID.
You need to add a valid UID and remove the default one to make the key usable:

```bash
$ gpg --edit-key <KEY_FINGERPRINT>
gpg> adduid
Real name: Your Name Here
Email address: your_email@example.com
......
gpg> uid 1
gpg> deluid
gpg> save
```

Or use:

```bash
./make-valid-gpg-key.sh <input-key> "Your Name Here" your_email@example.com
```

### Merge Key

Since cv25519 cannot be used as primary key, you need to merge the generated key with an existing key:

Reference: https://security.stackexchange.com/questions/32935/migrating-gpg-master-keys-as-subkeys-to-new-master-key

TLDR:

1. Primary key should be created earlier than subkey.
2. To preserve the subkey fingerprint, you need preserve the subkey creation time.

```bash
gpg -k --with-colons
gpg --with-keygrip -k
gpg --expert --faked-system-time="[sub key timestamp]\!" --ignore-time-conflict --edit-key [master key id]
addkey
13 (existing key)
```
