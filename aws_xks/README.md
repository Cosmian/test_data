# Running the AWS XKS tests

These are the AWS XKS tests, slightly adapted so that they can call a local KMS and run on macOS.

## Setup

You need `bash`version 4.2 or later.
If on macOS, install a recent version of bash using:

```sh
brew install bash
```

## Start the KMS

Start the KMS from the project root using:

```sh
RUST_LOG="info,cosmian_kms=debug" \
cargo run --features non-fips --bin cosmian_kms -- \
-c test_data/aws_xks/aws_xks.toml
```

## Create the AWS key encryption key

First create an AES 256-bit symmetric key.
From the root directory, run: 

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
sym keys create aws_xks_kek
```

Grant the `GetAttributes`, `Encrypt` and `Decrypt` operations to the AWS user `arn:aws:iam::123456789012:user/Alice`:

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
access-rights grant -i aws_xks_kek arn:aws:iam::123456789012:user/Alice get_attributes encrypt decrypt
```

## Create an "encrypt only" key

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
sym keys create encrypt_only_key
```

Grant the `GetAttributes` and `Encrypt` operations to the AWS user `arn:aws:iam::123456789012:user/Alice`:

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
access-rights grant -i encrypt_only_key arn:aws:iam::123456789012:user/Alice get_attributes encrypt
```

## Create a "decrypt only" key

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
sym keys create decrypt_only_key
```
Grant the `GetAttributes` and `Decrypt` operations to the AWS user `arn:aws:iam::123456789012:user/Alice`:

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms \
access-rights grant -i decrypt_only_key arn:aws:iam::123456789012:user/Alice get_attributes decrypt
```


## Run the tests

From the `test_data/aws_xks/scripts` directory, run:

on macOS:

```sh
<HOMEBREW_HOME>/bin/bash ./test_all
```

on Linux:

```sh
./test_all
```
