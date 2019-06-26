using KeyVaultExample.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace KeyVaultExample.Repositories
{
    public interface IKeyVaultRepository
    {
        Task<List<CertificateBundle>> GetCertificatesAsync();
        Task<byte[]> CreateLetsEncryptCertificateAsync(string certificateName, KeyProperties keyProperties, string subject, IEnumerable<string> subjectAlternativeNames, Dictionary<string, string> tags);
        Task CreateSelfSignedCertificateAsync(string certificateName, KeyProperties keyProperties, string subject, IEnumerable<string> subjectAlternativeNames, Dictionary<string, string> tags);
        Task MergeCertificateAsync(string certificateName, X509Certificate2Collection x509Certificates);
    }

    public class KeyVaultRepository
        : IKeyVaultRepository
    {
        private readonly Settings settings;
        private readonly IKeyVaultClient keyVaultClient;

        public KeyVaultRepository(IOptions<Settings> options, IKeyVaultClient keyVaultClient)
        {
            settings = options.Value;
            this.keyVaultClient = keyVaultClient;
        }

        public async Task<List<CertificateBundle>> GetCertificatesAsync()
        {
            var certificates = await keyVaultClient.GetCertificatesAsync(settings.VaultBaseUri.AbsoluteUri);
            var certificateList = certificates
                .Where(x => (x.Attributes.Expires.Value - DateTime.UtcNow).TotalDays < 30)
                .ToArray();

            var certificateBundles = new List<CertificateBundle>();
            foreach (var item in certificateList)
            {
                certificateBundles.Add(await keyVaultClient.GetCertificateAsync(item.Id));
            }

            return certificateBundles;
        }

        public async Task<byte[]> CreateLetsEncryptCertificateAsync(string certificateName, KeyProperties keyProperties, string subject, IEnumerable<string> subjectAlternativeNames, Dictionary<string, string> tags)
        {
            var certificatePolicy = new CertificatePolicy()
            {
                KeyProperties = new KeyProperties()
                {
                    KeyType = JsonWebKeyType.EllipticCurve,
                    Curve = JsonWebKeyCurveName.P256,
                },
                X509CertificateProperties = new X509CertificateProperties()
                {
                    Subject = subject,
                    SubjectAlternativeNames = new SubjectAlternativeNames(dnsNames: subjectAlternativeNames.ToList()),
                }
            };

            try
            {
                var certificateOperation = await keyVaultClient.CreateCertificateAsync(settings.VaultBaseUri.AbsoluteUri, certificateName, certificatePolicy, tags: tags);
                return certificateOperation.Csr;
            }
            catch (KeyVaultErrorException keyVaultErrorException)
            {
                Console.WriteLine($"Error ({keyVaultErrorException.Body.Error.Code}): {keyVaultErrorException.Body.Error.Message}");
                if (keyVaultErrorException.Body.Error.InnerError != null)
                {
                    var innerError = keyVaultErrorException.Body.Error.InnerError;
                    Console.WriteLine($"Inner Error ({innerError.Code}): {innerError.Message}");
                }
            }

            throw new InvalidOperationException("Creating a certificate failed...");
        }

        public async Task CreateSelfSignedCertificateAsync(string certificateName, KeyProperties keyProperties, string subject, IEnumerable<string> subjectAlternativeNames, Dictionary<string, string> tags)
        {
            var certificatePolicy = new CertificatePolicy()
            {
                KeyProperties = new KeyProperties()
                {
                    KeyType = JsonWebKeyType.EllipticCurve,
                    Curve = JsonWebKeyCurveName.P256,
                },
                X509CertificateProperties = new X509CertificateProperties()
                {
                    Subject = subject,
                    SubjectAlternativeNames = new SubjectAlternativeNames(dnsNames: subjectAlternativeNames.ToList()),
                },
                IssuerParameters = new IssuerParameters()
                {
                    Name = "Self",
                },
            };

            try
            {
                var certificateOperation = await keyVaultClient.CreateCertificateAsync(settings.VaultBaseUri.AbsoluteUri, certificateName, certificatePolicy, tags: tags);
                var encodedCertificate = Encoding.UTF8.GetString(certificateOperation.Csr);
            }
            catch (KeyVaultErrorException keyVaultErrorException)
            {
                Console.WriteLine($"Error ({keyVaultErrorException.Body.Error.Code}): {keyVaultErrorException.Body.Error.Message}");
                if (keyVaultErrorException.Body.Error.InnerError != null)
                {
                    var innerError = keyVaultErrorException.Body.Error.InnerError;
                    Console.WriteLine($"Inner Error ({innerError.Code}): {innerError.Message}");
                }
            }
        }

        public async Task MergeCertificateAsync(string certificateName, X509Certificate2Collection x509Certificates)
        {
            await keyVaultClient.MergeCertificateAsync(settings.VaultBaseUri.AbsoluteUri, certificateName, x509Certificates);
        }
    }
}
