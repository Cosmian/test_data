#!/bin/bash

# Generate the root key
openssl genpkey -algorithm RSA -out root.key

# Generate the root certificate
openssl req -x509 -days 3650 -key root.key -out root.crt -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=foo.com"

# Generate the intermediate key
openssl genpkey -algorithm RSA -out intermediate.key
# Create the intermediate certificate signing request
openssl req -new -key intermediate.key -out intermediate.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=intermediate.foo.com"
# Sign the intermediate certificate with the root certificate
openssl x509 -req -days 3650 -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -out intermediate.crt -extensions v3_ca -extfile <(echo -e "[v3_ca]\nbasicConstraints=critical,CA:TRUE")
openssl pkcs12 -export -out intermediate.p12 -inkey intermediate.key -in intermediate.crt -certfile root.crt -password pass:secret

# Generate the server key
openssl genpkey -algorithm RSA -out server.key
openssl req -new -key server.key -out server.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=server.foo.com"
openssl x509 -req -days 3650 -in server.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out server.crt
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile intermediate.crt -password pass:secret

# Generate an expired certificate for testing
openssl genpkey -algorithm RSA -out expired.key
openssl req -new -key expired.key -out expired.csr -subj "/C=FR/ST=IdG/L=Paris/O=GitHub/OU=Cosmian/CN=expired.foo.com"
# Create certificate with 1 day validity - since the existing one is already expired, we'll keep it short
openssl x509 -req -in expired.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out expired.crt -not_after 20240101000000Z -not_before 20230101000000Z
openssl pkcs12 -export -out expired.p12 -inkey expired.key -in expired.crt -certfile intermediate.crt -password pass:secret
