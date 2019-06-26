using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using DnsClient;
using KeyVaultExample.Exceptions;
using KeyVaultExample.Internal;
using KeyVaultExample.Models;
using KeyVaultExample.Services;
using Microsoft.Azure.Management.Dns.Fluent;
using Microsoft.Azure.Management.Dns.Fluent.Models;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Extensions.Options;
using Microsoft.Rest;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace KeyVaultExample.Repositories
{
    public interface ILetsEncryptRepository
    {
        Task<X509Certificate2Collection> IssueCertificateAsync(IEnumerable<string> dnsNames, byte[] csr);
    }

    /// <summary>
    /// Heavily based on https://raw.githubusercontent.com/shibayan/azure-keyvault-letsencrypt/master/AzureKeyVault.LetsEncrypt/SharedFunctions.cs
    /// </summary>
    public class LetsEncryptRepository
        : ILetsEncryptRepository
    {
        private readonly Settings settings;
        private readonly IAcmeHttpClient acmeHttpClient;
        private readonly IAzureAuthenticationService azureAuthenticationService;
        private readonly LookupClient lookupClient = new LookupClient() { UseCache = false };

        public LetsEncryptRepository(IOptions<Settings> options, IAcmeHttpClient acmeHttpClient, IAzureAuthenticationService azureAuthenticationService)
        {
            settings = options.Value;
            this.acmeHttpClient = acmeHttpClient;
            this.azureAuthenticationService = azureAuthenticationService;
        }

        public async Task<X509Certificate2Collection> IssueCertificateAsync(IEnumerable<string> dnsNames, byte[] csr)
        {
            await DnsPreconditionAsync(dnsNames);

            var orderDetails = await OrderAsync(dnsNames);
            var challengeResults = new List<ChallengeResult>();
            foreach (var authorization in orderDetails.Payload.Authorizations)
            {
                var result = await DnsAuthorizationAsync(authorization, Guid.NewGuid().ToString());
                await CheckDnsChallengeAsync(result);
                challengeResults.Add(result);
            }

            await AnswerChallengesAsync(challengeResults);
            await CheckIsReadyAsync(orderDetails);

            return await FinalizeOrderAsync(orderDetails, csr);
        }

        private async Task<AcmeProtocolClient> CreateAcmeClientAsync()
        {
            var account = default(AccountDetails);
            var accountKey = default(AccountKey);
            var acmeDir = default(ServiceDirectory);

            LoadState(ref account, "account.json");
            LoadState(ref accountKey, "account_key.json");
            LoadState(ref acmeDir, "directory.json");

            var acmeProtocolClient = new AcmeProtocolClient(acmeHttpClient.ToHttpClient(), acmeDir, account, accountKey?.GenerateSigner());
            if (acmeDir == null)
            {
                acmeDir = await acmeProtocolClient.GetDirectoryAsync();
                SaveState(acmeDir, "directory.json");
                acmeProtocolClient.Directory = acmeDir;
            }

            await acmeProtocolClient.GetNonceAsync();

            if (account == null || accountKey == null)
            {
                account = await acmeProtocolClient.CreateAccountAsync(new[] { "mailto:" + settings.LetsEncryptContacts }, true);

                accountKey = new AccountKey()
                {
                    KeyType = acmeProtocolClient.Signer.JwsAlg,
                    KeyExport = acmeProtocolClient.Signer.Export()
                };

                SaveState(account, "account.json");
                SaveState(accountKey, "account_key.json");
                acmeProtocolClient.Account = account;
            }

            return acmeProtocolClient;
        }

        private async Task<DnsManagementClient> CreateDnsManagementClientAsync()
        {
            var scopes = new List<string>() { "https://management.azure.com/user_impersonation" };
            var accessToken = await azureAuthenticationService.AuthenticateAsync(scopes);
            var tokenCredentials = new TokenCredentials(accessToken);
            var azureCredentials = new AzureCredentials(tokenCredentials, tokenCredentials, settings.TenantId, AzureEnvironment.AzureGlobalCloud);
            var restClient = RestClient
                .Configure()
                .WithEnvironment(AzureEnvironment.AzureGlobalCloud)
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .WithCredentials(azureCredentials)
                .Build();

            var dnsClient = new DnsManagementClient(restClient)
            {
                SubscriptionId = settings.SubscriptionId,
            };

            return dnsClient;
        }

        private async Task<ChallengeResult> DnsAuthorizationAsync(string authorizationUrl, string instanceId)
        {
            var acmeProtocolClient = await CreateAcmeClientAsync();
            var authorizationDetails = await acmeProtocolClient.GetAuthorizationDetailsAsync(authorizationUrl);
            var challenge = authorizationDetails.Challenges.First(x => x.Type == "dns-01");
            var challengeValidationDetails = AuthorizationDecoder.ResolveChallengeForDns01(authorizationDetails, challenge, acmeProtocolClient.Signer);

            var dnsManagementClient = await CreateDnsManagementClientAsync();
            var zone = (await dnsManagementClient.Zones.ListAsync()).First(x => challengeValidationDetails.DnsRecordName.EndsWith(x.Name));
            var resourceId = ParseResourceId(zone.Id);
            var acmeDnsRecordName = challengeValidationDetails.DnsRecordName.Replace("." + zone.Name, "");

            RecordSetInner recordSet;
            try
            {
                recordSet = await dnsManagementClient.RecordSets.GetAsync(resourceId["resourceGroups"], zone.Name, acmeDnsRecordName, RecordType.TXT);
            }
            catch
            {
                recordSet = null;
            }

            if (recordSet != null)
            {
                if (recordSet.Metadata == null || !recordSet.Metadata.TryGetValue("InstanceId", out var dnsInstanceId) || dnsInstanceId != instanceId)
                {
                    recordSet.Metadata = new Dictionary<string, string>
                    {
                        { "InstanceId", instanceId }
                    };

                    recordSet.TxtRecords.Clear();
                }

                recordSet.TTL = 60;
                recordSet.TxtRecords.Add(new TxtRecord(new[] { challengeValidationDetails.DnsRecordValue }));
            }
            else
            {
                recordSet = new RecordSetInner()
                {
                    TTL = 60,
                    Metadata = new Dictionary<string, string>
                    {
                        { "InstanceId", instanceId }
                    },
                    TxtRecords = new[]
                    {
                        new TxtRecord(new[] { challengeValidationDetails.DnsRecordValue })
                    }
                };
            }

            await dnsManagementClient.RecordSets.CreateOrUpdateAsync(resourceId["resourceGroups"], zone.Name, acmeDnsRecordName, RecordType.TXT, recordSet);
            return new ChallengeResult()
            {
                Url = challenge.Url,
                DnsRecordName = challengeValidationDetails.DnsRecordName,
                DnsRecordValue = challengeValidationDetails.DnsRecordValue
            };
        }

        private async Task CheckDnsChallengeAsync(ChallengeResult challengeResult)
        {
            var queryResult = await lookupClient.QueryAsync(challengeResult.DnsRecordName, QueryType.TXT);
            var txtRecords = queryResult.Answers
                .OfType<DnsClient.Protocol.TxtRecord>()
                .ToArray();

            if (txtRecords.Length == 0)
            {
                throw new LetsEncryptException($"{challengeResult.DnsRecordName} did not resolve.");
            }

            if (!txtRecords.Any(x => x.Text.Contains(challengeResult.DnsRecordValue)))
            {
                throw new LetsEncryptException($"{challengeResult.DnsRecordName} value is not correct.");
            }
        }

        private async Task<OrderDetails> OrderAsync(IEnumerable<string> dnsNames)
        {
            var acme = await CreateAcmeClientAsync();
            return await acme.CreateOrderAsync(dnsNames);
        }

        private async Task DnsPreconditionAsync(IEnumerable<string> dnsNames)
        {
            var dnsClient = await CreateDnsManagementClientAsync();
            var zones = await dnsClient.Zones.ListAsync();
            foreach (var hostName in dnsNames)
            {
                if (!zones.Any(x => hostName.EndsWith(x.Name)))
                {
                    throw new InvalidOperationException($"Azure DNS zone \"{hostName}\" is not found");
                }
            }
        }

        private async Task AnswerChallengesAsync(IEnumerable<ChallengeResult> challengeResults)
        {
            var acme = await CreateAcmeClientAsync();
            foreach (var challenge in challengeResults)
            {
                await acme.AnswerChallengeAsync(challenge.Url);
            }
        }

        private async Task CheckIsReadyAsync(OrderDetails orderDetails)
        {
            var acme = await CreateAcmeClientAsync();
            orderDetails = await acme.GetOrderDetailsAsync(orderDetails.OrderUrl, orderDetails);
            if (orderDetails.Payload.Status == "pending")
            {
                throw new LetsEncryptException("ACME domain validation is pending.");
            }

            if (orderDetails.Payload.Status == "invalid")
            {
                throw new InvalidOperationException("Invalid order status. Required retry at first.");
            }
        }

        private async Task<X509Certificate2Collection> FinalizeOrderAsync(OrderDetails orderDetails, byte[] csr)
        {
            var acme = await CreateAcmeClientAsync();
            var finalize = await acme.FinalizeOrderAsync(orderDetails.Payload.Finalize, csr);

            var certificateData = await acmeHttpClient.GetByteArrayAsync(finalize.Payload.Certificate);
            var x509Certificates = new X509Certificate2Collection();

            x509Certificates.Import(certificateData);
            return x509Certificates;
        }

        private static IDictionary<string, string> ParseResourceId(string resourceId)
        {
            var values = resourceId.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            return new Dictionary<string, string>
            {
                { "subscriptions", values[1] },
                { "resourceGroups", values[3] },
                { "providers", values[5] }
            };
        }

        private static void LoadState<T>(ref T value, string path)
        {
            var fullPath = Environment.ExpandEnvironmentVariables(@"%HOME%\.acme\" + path);
            if (!File.Exists(fullPath))
            {
                return;
            }

            var json = File.ReadAllText(fullPath);
            value = JsonConvert.DeserializeObject<T>(json);
        }

        private static void SaveState<T>(T value, string path)
        {
            var fullPath = Environment.ExpandEnvironmentVariables(@"%HOME%\.acme\" + path);
            var directoryPath = Path.GetDirectoryName(fullPath);

            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }

            var json = JsonConvert.SerializeObject(value, Formatting.Indented);
            File.WriteAllText(fullPath, json);
        }
    }
}
