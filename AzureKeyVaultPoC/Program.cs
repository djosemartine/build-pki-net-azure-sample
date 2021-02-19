using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureKeyVaultPoC
{
    class Program
    {
        private static readonly string EnvironmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        protected Program() { }
        static async Task Main()
        {
            Console.WriteLine("Hello World!");
            var configuration = ReadConfiguration();
            var authHelper = new AuthenticationHelper(configuration.Instance, configuration.TenantId
                , configuration.ClientId, configuration.Scopes);
            var acquireTokenResult = await authHelper.AcquireTokenAsync();
            Console.WriteLine($"Access Token: {acquireTokenResult.AccessToken}");
            Console.WriteLine($"Object ID: {acquireTokenResult.UserObjectId}");
            var certificate = await new RootCertificateHelper(configuration, acquireTokenResult.AccessToken)
                .GenerateRootCertificate();
            await WriteCertificateToFile(certificate);
        }

        public static Configuration ReadConfiguration()
        {
            var configurationRoot = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{EnvironmentName}.json")
                .Build();
            var configuration = new Configuration();
            configurationRoot.GetSection("KeyVaultOptions").Bind(configuration);
            return configuration;
        }

        private static async Task WriteCertificateToFile(X509Certificate2 certificate)
        {
            const string fileName = "RootCert.cer";
            var fullFilePath = Path.Combine(Environment.CurrentDirectory, fileName);
            await File.WriteAllTextAsync(fullFilePath, Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
            Console.WriteLine($"Stored public issuer certificate at '{fullFilePath}'");
        }
    }
}
