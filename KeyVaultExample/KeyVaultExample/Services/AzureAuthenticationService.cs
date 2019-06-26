using KeyVaultExample.Extensions;
using KeyVaultExample.Models;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using TextCopy;

namespace KeyVaultExample.Services
{
    public interface IAzureAuthenticationService
    {
        Task<string> AuthenticateAsync(IEnumerable<string> scopes);
    }

    public class AzureAuthenticationService
        : IAzureAuthenticationService
    {
        private readonly Settings settings;
        private Dictionary<string, string> AccessTokens { get; set; }

        public AzureAuthenticationService(IOptions<Settings> options)
        {
            AccessTokens = new Dictionary<string, string>();
            settings = options.Value;
        }

        public async Task<string> AuthenticateAsync(IEnumerable<string> scopes)
        {
            if (AccessTokens.ContainsKey(scopes.ToDictionaryKey())) return AccessTokens[scopes.ToDictionaryKey()];

            var publicClientApplicationOptions = new PublicClientApplicationOptions()
            {
                AzureCloudInstance = Enum.Parse<AzureCloudInstance>(settings.AzureCloudInstance, true),
                TenantId = settings.TenantId,
                ClientId = settings.ClientId,
            };
            var publicApplicationClient = PublicClientApplicationBuilder.CreateWithApplicationOptions(publicClientApplicationOptions).Build();
            var authenticationResult = await publicApplicationClient.AcquireTokenWithDeviceCode(scopes, (dcr) =>
            {
                Clipboard.SetText(dcr.UserCode);
                var url = dcr.VerificationUrl;
                try
                {
                    Process.Start(url);
                }
                catch
                {
                    // hack because of this: https://github.com/dotnet/corefx/issues/10361
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        url = url.Replace("&", "^&");
                        Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        Process.Start("xdg-open", url);
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        Process.Start("open", url);
                    }
                    else
                    {
                        throw;
                    }
                }

                Console.WriteLine($"{dcr.Message}");
                return Task.FromResult(0);
            }).ExecuteAsync();

            if (!AccessTokens.ContainsKey(scopes.ToDictionaryKey()))
            {
                AccessTokens.Add(scopes.ToDictionaryKey(), authenticationResult.AccessToken);
            }
            else
            {
                AccessTokens[scopes.ToDictionaryKey()] = authenticationResult.AccessToken;
            }

            return AccessTokens[scopes.ToDictionaryKey()];
        }
    }
}