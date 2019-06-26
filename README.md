# Key Vault Demo with Lets Encrypt

The goal of this is to create a console application example of how to create a self signed certificate or to have one signed by [Let's Encrypt](https://letsencrypt.org/).

## Pre-requisites

Run the following in Bash or WSL:

``` bash
az group create --name KeyVaultDemo --location westus2
az keyvault create --name mykeyvaultdemo --resource-group KeyVaultDemo
```

Then run the following in Bash or WSL to create an Azure AD Application Registration:

> Note to those poor souls who are not administrators inside their Azure AD tenant, this script will not work for you. Please send it to your administrator so that it can get the admin consent it needs to run KeyVault commands.

``` bash
./create-app.sh
```

Copy the output into the values below inside appsettings.json

## Configuration

Please create the following configuration inside your appsettings.json

``` json
{
  "Settings": {
    "AzureCloudInstance": "AzurePublic",
    "TenantId": "Tenant Id from Azure AD",
    "ClientId": "Client Id from Azure AD Application Registration",
    "SubscriptionId": "Subscription Id for Azure",
    "VaultBaseUri": "The Azure KeyVault Base Uri",
    "LetsEncryptUri": "Let's Encrypt Base Uri (most likely https://acme-v02.api.letsencrypt.org/)",
    "LetsEncryptContacts": "The contact email address registered to your DNS under Admin Contact"
  }
}
```

Finally modify the Program.cs to replace the values for the following:

``` csharp
            // Change variables below to configure the application.
            // Name of the self signed certificate in keyvault.
            var selfSignedKeyVaultName = "";

            // Name of the certificate signed by Let's Encrypt.
            var letsEncryptedKeyVaultName = "";

            // The subject for the self signed certificate.
            // Most likely something like CN=contoso.com
            var subjectName = "";

            // Subject alternative names
            // Most likely contoso.com
            var subjectAlternativeNames = new List<string>();
```

## Shout Out

The majority of this code is based on an awesome Azure Functions application that allows you to submit a certificate request against the function app and create a LetsEncrypt signed certificate. That repository is over at [azure-keyvault-letsencrypt](https://github.com/shibayan/azure-keyvault-letsencrypt) and was built by [Tatsuro Shibamura](https://github.com/shibayan).

![Thank you](https://media.giphy.com/media/3oz8xIsloV7zOmt81G/giphy.gif)
