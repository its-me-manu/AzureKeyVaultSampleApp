using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Identity;
using KeyVaultSampleApp.Interfaces.KeyVault;

namespace KeyVaultSampleApp.Services.KeyVault;

public class KeyVaultClientWrapper : IKeyVaultClient
{
    private readonly KeyClient _keyClient;
    private readonly SecretClient _secretClient;
    private readonly CryptographyClient _cryptographyClient;

    public KeyVaultClientWrapper(KeyClient keyClient, SecretClient secretClient, CryptographyClient cryptographyClient)
    {
        _keyClient = keyClient;
        _cryptographyClient = cryptographyClient;
        _secretClient = secretClient;
    }

    public async Task<KeyVaultKey> GetKeyAsync(string keyName, string keyVersion = null, CancellationToken cancellationToken = default)
    {
        return await _keyClient.GetKeyAsync(keyName, keyVersion, cancellationToken);
    }

    public async Task<EncryptResult> EncryptAsync(string keyName, string algorithm, byte[] plainText, CancellationToken cancellationToken = default)
    {
        return await _cryptographyClient.EncryptAsync(algorithm, plainText, cancellationToken);
    }

    public async Task<DecryptResult> DecryptAsync(string keyName, string algorithm, byte[] cipherText, CancellationToken cancellationToken = default)
    {
        return await _cryptographyClient.DecryptAsync(algorithm, cipherText, cancellationToken);
    }

    public async Task<KeyVaultSecret> GetSecretAsync(string vaultUrl, string secretName)
    {
        return await _secretClient.GetSecretAsync(secretName);
    }

    public async Task<KeyVaultSecret> SetSecretAsync(string vaultUrl, string secretName, string secret)
    {
        return await _secretClient.SetSecretAsync(secretName, secret);
    }

    public async Task DeleteSecretAsync(string vaultUrl, string secretName)
    {
        DeleteSecretOperation deleteOperation = await _secretClient.StartDeleteSecretAsync(secretName);
        // Purge or recover the deleted secret if soft delete is enabled.
        if (deleteOperation.Value.RecoveryId != null)
        {
            // Deleting a secret does not happen immediately. Wait for the secret to be deleted.
            DeletedSecret deletedSecret = await deleteOperation.WaitForCompletionAsync();

            // Purge the deleted secret.
            await _secretClient.PurgeDeletedSecretAsync(deletedSecret.Name);

            // You can also recover the deleted secret using StartRecoverDeletedSecretAsync,
            // which returns RecoverDeletedSecretOperation you can await like DeleteSecretOperation above.
        }
    }
}