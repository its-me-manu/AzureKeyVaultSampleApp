using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using KeyVaultSampleApp.Interfaces.KeyVault;
using KeyVaultSampleApp.Interfaces.SSH;
using KeyVaultSampleApp.Models;
using KeyVaultSampleApp.Services.KeyVault;

namespace KeyVaultSampleApp.Services.SSH;
public class SftpClientFactory : ISftpClientFactory
{
    private readonly IKeyVaultClient _keyVault;

    public SftpClientFactory(IKeyVaultClient keyVault)
    {
        _keyVault = keyVault;
    }

    public async Task<ISftpClient> Create(FtpSettings settings, Uri vaultUrl)
    {
        if (settings.AllowPrivateKeyAuthentication == true && !string.IsNullOrWhiteSpace(settings.PasswordKeyIdentifier)
                && !string.IsNullOrWhiteSpace(settings.PrivateKeyEncryptionIdentifier))
        {
            if (settings.PassPhraseEncrypted != null)
            {
                var passphrase = await _keyVault.DecryptAsync(settings.PasswordKeyIdentifier, EncryptionAlgorithm.RsaOaep.ToString(), settings.PassPhraseEncrypted);
                settings.PassPhrase = Encoding.UTF8.GetString(passphrase.Plaintext);
            }

            var privateKey = await _keyVault.GetSecretAsync(vaultUrl.ToString(), settings.PrivateKeyEncryptionIdentifier);
            settings.PrivateKeyContent = Encoding.UTF8.GetBytes(privateKey.Value);
        }
        else if (settings.AllowPrivateKeyAuthentication != true && String.IsNullOrEmpty(settings.Password) && !String.IsNullOrEmpty(settings.PasswordKeyIdentifier))
        {
            var response = await _keyVault.DecryptAsync(settings.PasswordKeyIdentifier, EncryptionAlgorithm.RsaOaep.ToString(), settings.PasswordEncrypted);
            settings.Password = Encoding.UTF8.GetString(response.Plaintext);
        }

        return SftpClientWrapper.Create(settings);
    }
}