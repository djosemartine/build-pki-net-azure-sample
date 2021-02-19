using Azure.Security.KeyVault.Certificates;
using System.Collections.Generic;

namespace AzureKeyVaultPoC
{
    public class Configuration
    {
        public bool CreateResources { get; set; }
        public string Instance { get; set; } = default!;
        public RootCertificate RootCertificate { get; set; } = default!;
        public string Uri { get; set; } = default!;
        public string ClientId { get; set; } = default!;
        public string TenantId { get; set; } = default!;
        public string[] Scopes { get; set; } = default!;
    }

    public class RootCertificate
    {
        public string Name { get; set; }
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public SubjectAlternativeNames SubjectAlternativeNames { get; set; }
        public IDictionary<string, string> Tags { get; set; }
    }
}
