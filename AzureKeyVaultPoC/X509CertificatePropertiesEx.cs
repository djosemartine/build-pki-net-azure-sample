using Azure.Security.KeyVault.Certificates;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace AzureKeyVaultPoC
{
    // This class is a hack to expose support for setting the "basic_constraints" certificate attribute.
    // See https://github.com/estiller/build-pki-net-azure-sample/issues/1
    // Future SDK versions might expose this natively so this class will become redundant
    [SuppressMessage("ReSharper", "IdentifierTypo")]
    public class X509CertificatePropertiesExtended
    {

        [JsonProperty(PropertyName = "subject")]
        public string Subject { get; set; }
        [JsonProperty(PropertyName = "ekus")]
        public IList<string> Ekus { get; set; }
        [JsonProperty(PropertyName = "sans")]
        public SubjectAlternativeNames SubjectAlternativeNames { get; set; }
        [JsonProperty(PropertyName = "key_usage")]
        public IList<string> KeyUsage { get; set; }
        [JsonProperty(PropertyName = "validity_months")]
        public int? ValidityInMonths { get; set; }
        public X509CertificatePropertiesExtended(string subject = null,
            IList<string> ekus = null,
            SubjectAlternativeNames subjectAlternativeNames = null,
            IList<string> keyUsage = null,
            int? validityInMonths = null,
            BasicConstraintsExtended basicConstraints = null)
        {
            Subject = subject;
            Ekus = ekus;
            SubjectAlternativeNames = subjectAlternativeNames;
            KeyUsage = keyUsage;
            ValidityInMonths = validityInMonths;
            BasicConstraints = basicConstraints;
        }

        [JsonProperty("basic_constraints")] public BasicConstraintsExtended BasicConstraints { get; set; }
        public class BasicConstraintsExtended
        {
            public BasicConstraintsExtended(bool isCa, int pathLenConstraint)
            {
                IsCA = isCa;
                PathLenConstraint = pathLenConstraint;
            }

            // ReSharper disable once InconsistentNaming
            [JsonProperty("ca")] public bool IsCA { get; set; }
            [JsonProperty("path_len_constraint")] public int PathLenConstraint { get; set; }
        }
    }
}
