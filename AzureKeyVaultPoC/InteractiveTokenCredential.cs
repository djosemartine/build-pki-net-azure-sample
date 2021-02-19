using Azure.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AzureKeyVaultPoC
{
    public class InteractiveTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            var configuration = Program.ReadConfiguration();
            var authHelper = new AuthenticationHelper(configuration.Instance, configuration.TenantId
                , configuration.ClientId, configuration.Scopes);
            var acquireTokenResult = await authHelper.AcquireTokenAsync();
            return new AccessToken(acquireTokenResult.AccessToken, DateTime.UtcNow.AddSeconds(60));
        }
    }
}
