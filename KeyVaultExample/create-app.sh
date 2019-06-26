#!/bin/bash

appName="KeyVaultApp"
password="$(</dev/urandom tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_`{|}~' | head -c 24; echo)"
identifierUri="api://key-vault-demo"

application=$(az ad app create --display-name "$appName" --required-resource-access @create-app-rra.json --identifier-uris "$identifierUri" --password "$password")
appId="$(jq -r '.appId' <<< $application)"
tenantId="$(az account show | jq -r '.tenantId')"
az ad app permission admin-consent --id "$appId"

cat << EOF
Please run this in the parent shell...

export tenantId="$tenantId"
export clientId="$appId"
export clientSecret="$password"
export audience="$identifierUri"
export issuer="https://sts.windows.net/$tenantId/"
EOF
