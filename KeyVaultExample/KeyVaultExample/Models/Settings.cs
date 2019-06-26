using System;

namespace KeyVaultExample.Models
{
    public class Settings
    {
        public string AzureCloudInstance { get; set; }

        public string TenantId { get; set; }

        public string ClientId { get; set; }

        public string SubscriptionId { get; set; }

        public Uri VaultBaseUri { get; set; }

        public Uri LetsEncryptUri { get; set; }

        public string LetsEncryptContacts { get; set; }
    }
}
