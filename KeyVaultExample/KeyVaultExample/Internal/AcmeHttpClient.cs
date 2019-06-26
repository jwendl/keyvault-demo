using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace KeyVaultExample.Internal
{
    public interface IAcmeHttpClient
    {
        Task<byte[]> GetByteArrayAsync(string requestUri);
        Task<byte[]> GetByteArrayAsync(Uri requestUri);
        HttpClient ToHttpClient();
    }

    internal class AcmeHttpClient
        : HttpClient, IAcmeHttpClient
    {
        public HttpClient ToHttpClient()
        {
            return this as HttpClient;
        }
    }
}
