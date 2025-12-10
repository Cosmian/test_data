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

From the root directory, run: 

```sh
cosmian -c test_data/aws_xks/cosmian_cli.toml kms sym keys create aws_xks_kek
```

## Run the tests

From the `test_data/aws_xks/scripts` directory, run:

on macOS:

```sh
<HOMEBREW_HOME>/bin/bash ./test_get_health_status
```

on Linux:

```sh
./test_get_health_status
```
