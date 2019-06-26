using KeyVaultExample.Internal;
using KeyVaultExample.Models;
using KeyVaultExample.Repositories;
using KeyVaultExample.Services;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace KeyVaultExample
{
    class Program
    {
        static async Task Main()
        {
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

            // Tags for the resources created in keyvault.
            var tags = new Dictionary<string, string>
            {
                { "cert-type", "Let's Encrypt" }
            };

            // The type of certificate you'd like to request for.
            var keyProperties = new KeyProperties()
            {
                KeyType = JsonWebKeyType.EllipticCurve,
                Curve = JsonWebKeyCurveName.P256,
            };

            // Don't change below unless you want to.
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location))
                .AddJsonFile("appsettings.json")
                .Build();

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddOptions();
            serviceCollection.Configure<Settings>(options => configuration.GetSection(nameof(Settings)).Bind(options));

            serviceCollection.AddScoped<IKeyVaultClient, KeyVaultClient>((sp) =>
            {
                var keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(async (authority, resource, scope) =>
                {
                    var azureAuthenticationService = sp.GetRequiredService<IAzureAuthenticationService>();
                    var scopes = new List<string>() { "https://vault.azure.net/user_impersonation" };
                    return await azureAuthenticationService.AuthenticateAsync(scopes.AsEnumerable());
                }));

                return keyVaultClient;
            });

            serviceCollection.AddScoped<IAcmeHttpClient, AcmeHttpClient>((sp) =>
            {
                var options = sp.GetRequiredService<IOptions<Settings>>();
                var settings = options.Value;
                return new AcmeHttpClient() { BaseAddress = new Uri(settings.LetsEncryptUri.AbsoluteUri) };
            });

            serviceCollection.AddScoped<IAzureAuthenticationService, AzureAuthenticationService>();
            serviceCollection.AddScoped<IKeyVaultRepository, KeyVaultRepository>();
            serviceCollection.AddScoped<ILetsEncryptRepository, LetsEncryptRepository>();
            var serviceProvider = serviceCollection.BuildServiceProvider();

            var keyVaultRepository = serviceProvider.GetRequiredService<IKeyVaultRepository>();
            var letsEncryptRepository = serviceProvider.GetRequiredService<ILetsEncryptRepository>();

            await keyVaultRepository.CreateSelfSignedCertificateAsync(selfSignedKeyVaultName, keyProperties, subjectName, subjectAlternativeNames, tags);

            var csr = await keyVaultRepository.CreateLetsEncryptCertificateAsync(letsEncryptedKeyVaultName, keyProperties, subjectName, subjectAlternativeNames, tags);
            var certificates = await letsEncryptRepository.IssueCertificateAsync(subjectAlternativeNames, csr);
            await keyVaultRepository.MergeCertificateAsync(letsEncryptedKeyVaultName, certificates);
        }
    }
}
