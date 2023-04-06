using KeyVaultSampleApp.Models;

namespace KeyVaultSampleApp.Interfaces.SSH;
public interface ISftpClientFactory
{
    Task<ISftpClient> Create(FtpSettings settings, Uri vaultUrl);
}