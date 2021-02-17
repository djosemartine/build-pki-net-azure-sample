using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace BuildPkiSample.Setup
{
    internal class Program
    {
        protected Program() { }
        public static async Task Main()
        {
            var configuration = ReadConfiguration();
            var authHelper = new AuthenticationHelper(configuration.Instance, configuration.TenantId,
                 configuration.ClientId, AuthenticationHelper.AzureManagementScopes);
            var acquireTokenResult = await authHelper.AcquireTokenAsync();
            Console.WriteLine($"Access Token: {acquireTokenResult.AccessToken}");
            Console.WriteLine($"Object ID: {acquireTokenResult.UserObjectId}");
            if (!configuration.CreateResources) return;
            await new ResourceManagementHelper(configuration, acquireTokenResult).CreateAzureResourcesAsync(false);
        }

        private static Configuration ReadConfiguration()
        {
            var configurationRoot = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddUserSecrets<Program>()
                .Build();
            var configuration = configurationRoot.Get<Configuration>();
            return configuration;
        }
    }
}
