namespace KeyVaultSampleApp.Interfaces.SSH;
public interface ISftpClient : IDisposable
{
    void ChangeDirectory(string path);
    void Connect();
    void DeleteFile(string filename, bool ignoreFailures = false);
    void Disconnect();
    Task UploadAsync(Stream stream, string filename, bool canOverride);
    string GetHostKeyFingerPrints();
}