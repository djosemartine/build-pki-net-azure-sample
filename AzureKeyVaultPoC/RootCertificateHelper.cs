using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Rest;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static AzureKeyVaultPoC.X509CertificatePropertiesExtended;

namespace AzureKeyVaultPoC
{
    public class RootCertificateHelper
    {
        private const string RootSubjectName = "Build PKI Sample CA";

        private readonly string _vaultBaseUrl;
        private readonly Uri _vaultBaseUri;
        private readonly string _certificateName;
        private readonly string _accessToken;
        private readonly Configuration _configuration;

        public RootCertificateHelper(Configuration configuration, string accessToken)
        {
            _vaultBaseUrl = configuration.Uri;
            Uri.TryCreate(configuration.Uri, UriKind.Absolute, out _vaultBaseUri);
            _certificateName = configuration.RootCertificate.Name;
            _accessToken = accessToken;
            _configuration = configuration;
        }

        public async Task<X509Certificate2> GenerateRootCertificate()
        {
            // OPTION 1: Legacy KeyVault Client
            var client = new KeyVaultClient(new TokenCredentials(_accessToken));
            return await CreateCertificateInKeyVaultAsync(client);
            // OPTION 2: Default Azure Credential
            // DefaultAzureCredential credential = new DefaultAzureCredential(
            //new DefaultAzureCredentialOptions
            //{
            //    InteractiveBrowserTenantId = _configuration.TenantId,
            //    AuthorityHost = new Uri("https://login.microsoftonline.us", UriKind.Absolute),
            //    ExcludeEnvironmentCredential = true,
            //    ExcludeManagedIdentityCredential = true
            //});
            // OPTION 3: Interactive Token Credential
            //var secretCredential = new SecretClient(_vaultBaseUri, new InteractiveTokenCredential());
            //var value = await secretCredential.GetSecretAsync("key");
            // Using Client Certificate
            //var certificateClient = new CertificateClient(_vaultBaseUri, new InteractiveTokenCredential());
            //return await CreateCertificateInKeyVaultAsync(certificateClient);
        }

        // NOTE - if you'd like to create the root certificate locally with .NET then this would be the way to go.
        // However, this exposes the private key on the local machine which we'd rather avoid. Instead, use the alternative
        // of generating the root certificate directly on Azure Key-Vault.
        //
        // ReSharper disable once UnusedMember.Local
        private Task<X509Certificate2> CreateSelfSignedCertificateAndUploadAsync(KeyVaultClient client)
        {
            var certificate = CreateSelfSignedCertificateAndUpload();
            return ImportCertificateToKeyVaultAsync(client, certificate);
        }

        private X509Certificate2 CreateSelfSignedCertificateAndUpload()
        {
            var certificateKey = RSA.Create();
            var subjectDistinguishedName = new X500DistinguishedName("CN=" + RootSubjectName);
            var request = new CertificateRequest(subjectDistinguishedName, certificateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, true, 1, true));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.1") }, false));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        }

        private async Task<X509Certificate2> ImportCertificateToKeyVaultAsync(KeyVaultClient client, X509Certificate2 certificate)
        {
            CertificateBundle certificateBundle = await client.ImportCertificateAsync(
                _vaultBaseUrl,
                _certificateName,
                new X509Certificate2Collection(certificate),
                new Microsoft.Azure.KeyVault.Models.CertificatePolicy(
                    keyProperties: new KeyProperties(false, "RSA", 2048, false),
                    secretProperties: new Microsoft.Azure.KeyVault.Models.SecretProperties("application/x-pkcs12")));
            return new X509Certificate2(certificateBundle.Cer);
        }

        private async Task<X509Certificate2> CreateCertificateInKeyVaultAsync(KeyVaultClient client)
        {
            var certificatePolicy = new Microsoft.Azure.KeyVault.Models.CertificatePolicy(
                    keyProperties: new KeyProperties(false, "RSA", 2048, false),
                    x509CertificateProperties: new X509CertificatePropertiesEx(
                        "CN=" + _configuration.RootCertificate.Subject,
                        keyUsage: new List<string> { X509KeyUsageFlags.KeyCertSign.ToString() },
                        ekus: new List<string> { "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1" },
                        basicConstraints: new X509CertificatePropertiesEx.BasicConstraintsExtension(isCa: true, pathLenConstraint: 2)),
                    lifetimeActions: new List<Microsoft.Azure.KeyVault.Models.LifetimeAction> {
                                    new Microsoft.Azure.KeyVault.Models.LifetimeAction(
                                        new Trigger(daysBeforeExpiry: 15),
                                        new Microsoft.Azure.KeyVault.Models.Action(ActionType.AutoRenew)) },
                    issuerParameters: new IssuerParameters("Self"));
            var certificateOperation = await client.CreateCertificateAsync(
                _vaultBaseUrl,
                _certificateName,
                certificatePolicy
                );

            while (certificateOperation.Status == "inProgress")
            {
                Console.WriteLine($"Creation of certificate '{_certificateName}' is in progress");
                await Task.Delay(1000);
                certificateOperation = await client.GetCertificateOperationAsync(_vaultBaseUrl, _certificateName);
            }

            Console.WriteLine($"Creation of certificate '{_certificateName}' is in status '{certificateOperation.Status}'");

            var certificate = await client.GetCertificateAsync(_vaultBaseUrl, _certificateName);
            return new X509Certificate2(certificate.Cer);
        }
        // This class is a hack to expose support for setting the "basic_constraints" certificate attribute.
        // See https://github.com/estiller/build-pki-net-azure-sample/issues/1
        // Future SDK versions might expose this natively so this class will become redundant
        [SuppressMessage("ReSharper", "IdentifierTypo")]
        private class X509CertificatePropertiesEx : X509CertificateProperties
        {
            public X509CertificatePropertiesEx(string? subject = null,
                IList<string>? ekus = null,
                Microsoft.Azure.KeyVault.Models.SubjectAlternativeNames? subjectAlternativeNames = null,
                IList<string>? keyUsage = null,
                int? validityInMonths = null,
                BasicConstraintsExtension? basicConstraints = null)
                : base(subject, ekus, subjectAlternativeNames, keyUsage, validityInMonths)
            {
                BasicConstraints = basicConstraints;
            }

            [JsonProperty("basic_constraints")] public BasicConstraintsExtension? BasicConstraints { get; set; }

            public class BasicConstraintsExtension
            {
                public BasicConstraintsExtension(bool isCa, int pathLenConstraint)
                {
                    IsCA = isCa;
                    PathLenConstraint = pathLenConstraint;
                }

                // ReSharper disable once InconsistentNaming
                [JsonProperty("ca")] public bool IsCA { get; set; }
                [JsonProperty("path_len_constraint")] public int PathLenConstraint { get; set; }
            }
        }
        /// <summary>
        /// https://github.com/Azure/azure-rest-api-specs/issues/11962
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>

        private async Task<X509Certificate2> CreateCertificateInKeyVaultAsync(CertificateClient client)
        {
            var certificatePolicy = new CertificatesPolicyExtended(
                    "Self",
                    _configuration.RootCertificate.Subject,
                    _configuration.RootCertificate.SubjectAlternativeNames)
            {
                // https://certificate.transparency.dev/
                //CertificateTransparency = true,
                //CertificateType = ??
                Exportable = false,
                KeySize = 2048,
                KeyType = new CertificateKeyType("RSA"),
                ReuseKey = false,
                ContentType = new Azure.Security.KeyVault.Certificates.CertificateContentType(
                    Azure.Security.KeyVault.Certificates.CertificateContentType.Pkcs12.ToString()),
                ValidityInMonths = 12,
                Enabled = true,
                //X509CertificateProperties = new X509CertificatePropertiesExtended(_configuration.RootCertificate.Subject,
                //new List<string> { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" },
                //_configuration.RootCertificate.SubjectAlternativeNames,
                //new List<string> { X509KeyUsageFlags.KeyCertSign.ToString() },
                //validityInMonths: 11,
                //basicConstraints: new BasicConstraintsExtended(isCa: true, pathLenConstraint: 2))
            };
            // https://tools.ietf.org/html/rfc3280#section-4.2.1.3
            certificatePolicy.KeyUsage.Add(new CertificateKeyUsage(X509KeyUsageFlags.KeyCertSign.ToString()));
            // OID notation
            // http://www.oid-info.com/cgi-bin/display?oid=1.3.6.1.5.5.7.3.1&a=display
            // https://tools.ietf.org/html/rfc3280#section-4.2.1.13
            certificatePolicy.EnhancedKeyUsage.Add("1.3.6.1.5.5.7.3.1");
            certificatePolicy.EnhancedKeyUsage.Add("1.3.6.1.5.5.7.3.2");
            // At most one action is required
            var autoRenewAction = new CertificatePolicyAction(CertificatePolicyAction.AutoRenew.ToString());
            certificatePolicy.LifetimeActions.Add(new Azure.Security.KeyVault.Certificates.LifetimeAction(autoRenewAction)
            {
                DaysBeforeExpiry = 15
            });
            var certificateOperation = await client.StartCreateCertificateAsync(
                    _certificateName,
                    certificatePolicy,
                    enabled: true,
                    _configuration.RootCertificate.Tags);
            var keyVaultCert = await certificateOperation.WaitForCompletionAsync();
            Console.WriteLine($"Certificate '{_certificateName}' created successfully '{keyVaultCert.Value}'");
            var certificate = await client.GetCertificateAsync(_certificateName);
            return new X509Certificate2(certificate.Value.Cer);
        }


    }
}
