## gpg-fingerprint-filter-gpu

Generate an OpenPGP key whose fingerprint matches a specific pattern.

Get your lucky key! CUDA powered, so fast!

```
$ ./gpg-fingerprint-filter-gpu --help
  gpg-fingerprint-filter-gpu [OPTIONS] <pattern> <output>

  <pattern>                   Key pattern to match, for example 'X{8}|(AB){4}'
  <output>                    Save secret key to this path
  -a, --algorithm <ALGO>      PGP key algorithm [default: rsa]
  -M, --match-mode <MODE>     Match mode: prefix, suffix, either, both [default: prefix]
  -t, --time-offset <N>       Max key timestamp offset [default: 15552000]
  -w, --thread-per-block <N>  CUDA thread number per block [default: 512]
  -j, --gpg-thread <N>        Number of threads to generate keys [default: 12]
  -b, --base-time <N>         Base key timestamp (0 means current time) [default: 0]
  -h, --help
```

### Pattern

- By default it matches the beginning of a fingerprint.
- Use `--match-mode suffix` to match the end of a fingerprint.
- Use `--match-mode either` to match either the beginning or the end.
- Use `--match-mode both` to require a match at both the beginning and the end.
- A hex digit means itself.
- Other Latin alphabets (`g` to `z`) are to match any hex digit.
- `{N}` to repeat previous digit or group for N times.
- `(PATTERN)` a group pattern.
- Use `|` to split multiple patterns.

Examples:

- `deadbeef` equals to regex `^deadbeef` in the default `prefix` mode
- `deadbeef --match-mode suffix` equals to regex `deadbeef$`
- `deadbeef --match-mode both` equals to regex `^deadbeef.*deadbeef$`
- `x{8}` equals to regex `^([0-9a-f])\1{7}` in the default `prefix` mode
- `(xy){4}` equals to regex `^([0-9a-f][0-9a-f])\1{3}` in the default `prefix` mode

### Import Key

Import the generated private key:

```
$ gpg --allow-non-selfsigned-uid --import private.pgp
```

The private key file doesn't have a self-signed UID on it. GPG will display `NONAME` as the default UID.
You need to add a valid UID and remove the default one to make the key usable:

```
$ gpg --edit-key <KEY_FINGERPRINT>
gpg> adduid
Real name: Your Name Here
Email address: your_email@example.com
......
gpg> uid 1
gpg> deluid
gpg> save
```

### Merge Key

Since cv25519 cannot be used as primary key, you need to merge the generated key with an existing key:

Reference: https://security.stackexchange.com/questions/32935/migrating-gpg-master-keys-as-subkeys-to-new-master-key

TLDR:

1. Primary key should be created earlier than subkey. 
2. To persevere the subkey fingerprint, you need perserve the subkey creation time.

```
gpg -k --with-colons
gpg --with-keygrip -k
gpg --expert --faked-system-time="[sub key timestamp]\!" --ignore-time-conflict --edit-key [master key id]
addkey
13 (existing key)
```
