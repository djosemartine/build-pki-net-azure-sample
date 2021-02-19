using Azure.Security.KeyVault.Certificates;
using Newtonsoft.Json;

namespace AzureKeyVaultPoC
{
    public class CertificatesPolicyExtended : CertificatePolicy
    {
        public CertificatesPolicyExtended(string issuerName, string subject) : base(issuerName, subject)
        {
        }

        public CertificatesPolicyExtended(string issuerName, SubjectAlternativeNames subjectAlternativeNames) : base(issuerName, subjectAlternativeNames)
        {
        }

        public CertificatesPolicyExtended(string issuerName, string subject,
            SubjectAlternativeNames subjectAlternativeNames, X509CertificatePropertiesExtended x509CertificateProperties = null)
            : base(issuerName, subject, subjectAlternativeNames)
        {
            X509CertificateProperties = x509CertificateProperties;
        }

        [JsonProperty("x509_props")] public X509CertificatePropertiesExtended X509CertificateProperties { get; set; }
    }
}
