#!/bin/bash

# Simple script to find expired PKCS12 certificates
# This script focuses on just showing expired certificates with details

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Expired PKCS12 Certificate Detection ===${NC}"
echo "Current date: $(date)"
echo

cd "$(dirname "$0")" 2>/dev/null || cd test_data 2>/dev/null || { echo "Error: Cannot find test_data directory"; exit 1; }

expired_found=false

# Common passwords to try
passwords=("" "password" "test" "cosmian" "kms" "123456" "secret")

find . -name "*.p12" -type f | while read -r p12file; do
    echo -e "${YELLOW}Checking: $p12file${NC}"

    cert_extracted=false
    for password in "${passwords[@]}"; do
        if cert_content=$(openssl pkcs12 -in "$p12file" -nokeys -clcerts -passin pass:"$password" 2>/dev/null); then
            cert_extracted=true
            break
        fi
    done

    if [ "$cert_extracted" = false ]; then
        echo -e "  ${RED}❌ Cannot extract certificate (protected/invalid)${NC}"
        continue
    fi

    # Extract certificate details
    not_after=$(echo "$cert_content" | openssl x509 -noout -enddate | cut -d= -f2)
    subject=$(echo "$cert_content" | openssl x509 -noout -subject | cut -d= -f2-)

    # Check if expired
    if ! openssl x509 -checkend 0 -noout <<< "$cert_content" >/dev/null 2>&1; then
        echo -e "  ${RED}🚨 EXPIRED CERTIFICATE FOUND!${NC}"
        echo -e "  Subject: $subject"
        echo -e "  Expired on: $not_after"
        expired_found=true
    else
        echo -e "  ${GREEN}✅ Valid certificate${NC}"
    fi
    echo
done

if [ "$expired_found" = true ]; then
    echo -e "${RED}⚠️  Expired certificates detected in test_data folder!${NC}"
    exit 1
else
    echo -e "${GREEN}✅ No expired certificates found${NC}"
    exit 0
fi
