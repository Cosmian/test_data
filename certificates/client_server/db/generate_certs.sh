#!/bin/bash

# Script to generate certificates for database mTLS testing
# Generates server and client certificates for PostgreSQL and MySQL

# on MacOS, you should pass a link to an actually installed openssl binary, and not use the default `libressl`
# which generates PKCS12 files with the deprecated RC2 algorithm
OPENSSL_BIN=${1:-openssl}

# Use the existing CA from the parent directory
CA_CERT=../ca/ca.crt
CA_KEY=../ca/ca.key

if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
  echo "Error: CA certificate or key not found in ../ca/"
  echo "Please run the parent generate_certs.sh first"
  exit 1
fi

## PostgreSQL Server Cert

# Generate private key for postgres server
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out postgres-server.key

# Generate certificate signing request for postgres server
$OPENSSL_BIN req -new -key postgres-server.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=postgres" -out postgres-server.csr

# Generate certificate for postgres server signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in postgres-server.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out postgres-server.crt

## PostgreSQL Client Cert

# Generate private key for postgres client
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out postgres-client.key

# Generate certificate signing request for postgres client
$OPENSSL_BIN req -new -key postgres-client.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kms" -out postgres-client.csr

# Generate certificate for postgres client signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in postgres-client.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out postgres-client.crt

## MySQL Server Cert

# Generate private key for mysql server
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out mysql-server.key

# Generate certificate signing request for mysql server
$OPENSSL_BIN req -new -key mysql-server.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=mysql" -out mysql-server.csr

# Generate certificate for mysql server signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in mysql-server.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out mysql-server.crt

## MySQL Client Cert (PKCS12 format required for native-tls)

# Generate private key for mysql client
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out mysql-client.key

# Generate certificate signing request for mysql client
$OPENSSL_BIN req -new -key mysql-client.key -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kms" -out mysql-client.csr

# Generate certificate for mysql client signed by our own CA
$OPENSSL_BIN x509 -req -days 3650 -in mysql-client.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out mysql-client.crt

# Generate a PKCS12 file for MySQL client (required by native-tls)
$OPENSSL_BIN pkcs12 -export -out mysql-client.p12 -inkey mysql-client.key -in mysql-client.crt -certfile $CA_CERT -password pass:password

echo "Certificates generated successfully!"
echo "PostgreSQL:"
echo "  - Server: postgres-server.{key,crt}"
echo "  - Client: postgres-client.{key,crt}"
echo "MySQL:"
echo "  - Server: mysql-server.{key,crt}"
echo "  - Client: mysql-client.{key,crt,p12}"
