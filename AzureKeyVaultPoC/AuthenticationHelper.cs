﻿using ConsoleTools;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace AzureKeyVaultPoC
{
    internal class AuthenticationHelper
    {
        private readonly string _clientId;
        private readonly string _tenantId;
        private readonly string _instance;
        private readonly string[] _scopes;

        public AuthenticationHelper(string instance, string tenantId, string clientId, string[] scopes)
        {
            _clientId = clientId;
            _tenantId = tenantId;
            _scopes = scopes;
            _instance = instance;
        }

        public async Task<AcquireTokenResult> AcquireTokenAsync()
        {
            var app = PublicClientApplicationBuilder.Create(_clientId)
                .WithTenantId(_tenantId)
                .WithAuthority($"{_instance}/{_tenantId}")
                .WithDefaultRedirectUri()
                .Build();

            var storageCreationProperties = new StorageCreationPropertiesBuilder("tokenCache.dat", ".", _clientId).Build();
            (await MsalCacheHelper.CreateAsync(storageCreationProperties)).RegisterCache(app.UserTokenCache);
            var account = await GetAccountAsync(app);
            AuthenticationResult authenticationResult;
            try
            {
                authenticationResult = await app.AcquireTokenSilent(_scopes, account).ExecuteAsync();
            }
            catch (MsalUiRequiredException)
            {
                authenticationResult = await app.AcquireTokenInteractive(_scopes).ExecuteAsync();
            }

            return new AcquireTokenResult(authenticationResult.AccessToken , ExtractObjectId(authenticationResult.IdToken));
        }

        private static async Task<IAccount> GetAccountAsync(IPublicClientApplication app)
        {
            var accounts = await app.GetAccountsAsync();
            var accountList = accounts.ToList();
            switch (accountList.Count)
            {
                case 0:
                    return null;
                case 1:
                    return accountList[0];
            }

            IAccount result = null;
            var menu = new ConsoleMenu()
                .AddRange(accountList.Select(currentAccount => new Tuple<string, Action>(currentAccount.Username, () => result = currentAccount)))
                .Configure(config => { config.Title = "Choose an account"; });
            menu.Show();

            return result;
        }

        private static string ExtractObjectId(string idToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = tokenHandler.ReadJwtToken(idToken);
            return jwtToken.Claims.First(claim => claim.Type == "oid").Value;
        }
    }
}
