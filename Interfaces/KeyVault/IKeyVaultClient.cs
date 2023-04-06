using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;

namespace KeyVaultSampleApp.Interfaces.KeyVault;
public interface IKeyVaultClient
{
    Task<KeyVaultKey> GetKeyAsync(string keyName, string keyVersion, CancellationToken cancellationToken = default);
    Task<EncryptResult> EncryptAsync(string keyName, string algorithm, byte[] plainText, CancellationToken cancellationToken = default);
    Task<DecryptResult> DecryptAsync(string keyName, string algorithm, byte[] cipherText, CancellationToken cancellationToken = default);
    Task<KeyVaultSecret> SetSecretAsync(string vaultUrl, string secretName, string secret);
    Task<KeyVaultSecret> GetSecretAsync(string vaultUrl, string secretName);
    Task DeleteSecretAsync(string vaultUrl, string secretName);
}