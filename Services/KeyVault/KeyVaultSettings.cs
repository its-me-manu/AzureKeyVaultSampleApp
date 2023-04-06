namespace KeyVaultSampleApp.Services.KeyVault;

public class KeyVaultSettings
{
    public string TenantId { get; set; }
    public string KeyId { get; set; }
    public string ClientSecret { get; set; }
    public Uri VaultUri { get; set; }
    public string CryptoKeyName { get; set; }
}