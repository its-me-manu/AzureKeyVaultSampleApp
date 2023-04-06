namespace KeyVaultSampleApp.Models;
public class FtpSettings
{
    public long Id {get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
    public string Server { get; set; }
    public int Port { get; set; }
    public string Directory { get; set; }
    public string PasswordKeyIdentifier { get; set; }
    public byte[] PasswordEncrypted { get; set; }
    public bool? AllowPrivateKeyAuthentication { get; set; }
    public byte[] PassPhraseEncrypted { get; set; }
    public string PrivateKeyEncryptionIdentifier { get; set; }
    public byte[] PrivateKeyContent { get; set; }
    public string PassPhrase { get; set; }
    public bool IsEnable { get; set; }
    public string HostKeyFingerPrint { get; set; }
    public bool IsFingerPrintValid {get; set; }
}