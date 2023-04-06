using System.Text;
using Microsoft.AspNetCore.Mvc;
using KeyVaultSampleApp.Interfaces.KeyVault;
using KeyVaultSampleApp.Interfaces.SSH;
using KeyVaultSampleApp.Models;
using KeyVaultSampleApp.Services;

namespace Sample_MVC.Controllers;

[ApiController]
[Route("api/ftpsettings")]
public class FTPSettingsController : ControllerBase
{

    private readonly ILogger<FTPSettingsController> _logger;
    private readonly ISftpClientFactory _sftpClientFactory;
    public static IConfiguration _configuration;

    public FTPSettingsController(ILogger<FTPSettingsController> logger,
        ISftpClientFactory sftpClientFactory, 
        IConfiguration configuration)
    {
        _logger = logger;
        _sftpClientFactory = sftpClientFactory;
        _configuration = configuration;
    }

    [HttpGet(Name = "GetFTPSettings")]
    public IEnumerable<FtpSettings> Get()
    {
        return new List<FtpSettings>();
    }

    [HttpPost]
    public async Task<bool> Post()
    {
        var ftpSettings = new FtpSettings()
        {
            Id = 1,
            Server = "20.245.116.71",
            UserName = "sftpuser",
            Password = "",
            Port = 22,
            Directory = "/home/sftpuser"
        };

        return await UpdateFTPSettings(ftpSettings);
        
    }

    private async Task<bool> UpdateFTPSettings(FtpSettings ftpSettings, IFormFileCollection files = null)
    {
        var keyVaultSettings = _configuration.GetSection("KeyVaultSettings");
        Uri keyVaultUri = new Uri(keyVaultSettings["VaultUri"], UriKind.Absolute);

        if (string.IsNullOrWhiteSpace(ftpSettings.Directory)) //Assign default directory if empty.
                ftpSettings.Directory = "/";
            
            if (ftpSettings.Port == 0) //Assign default port if empty.
                ftpSettings.Port = 22;

            ftpSettings = FTPSettingsHelper.GetPrivateKey(files, ftpSettings);
            
            if(ftpSettings.Server != ftpSettings.Server)
            {
                ftpSettings.IsFingerPrintValid = false;
            }
            
            if (ftpSettings.AllowPrivateKeyAuthentication != true && string.IsNullOrWhiteSpace(ftpSettings.Password))
            {
                try
                {
                    using(var sftp = await _sftpClientFactory.Create(ftpSettings, keyVaultUri))
                    {
                        sftp.Connect();
                        sftp.Disconnect();
                        ftpSettings.Password = ftpSettings.Password;
                    }
                }
                catch (InvalidOperationException)
                {
                    throw new BadHttpRequestException($"Invalid operation. This can happen if the passphrase is wrong. Server: {ftpSettings.Server}, Account: {ftpSettings.Id}");
                }
                catch (Exception ex)
                {
                    throw new BadHttpRequestException(ex.Message + $"Server: {ftpSettings.Server}, Account: {ftpSettings.Id}");
                }
            }

            var validationStatus = FTPSettingsHelper.ValidatePostData(ftpSettings);
            if (!validationStatus.Item1)
            {
                throw new BadHttpRequestException(validationStatus.Item2);
            }

            if (ftpSettings.Password == null)
            {
                ftpSettings.Password = String.Empty;
            }

            try
            {
                using (var sftp = await _sftpClientFactory.Create(ftpSettings, keyVaultUri))
                {
                    sftp.Connect();
                    sftp.ChangeDirectory(ftpSettings.Directory);
                    const string testFileName = "Proteus2 Connection Test (Okay To Delete).txt";
                    using (var stream = new MemoryStream(Encoding.UTF8.GetBytes("Testing upload from Proteus2. This file can be deleted.")))
                    {
                        stream.Position = 0;
                        await sftp.UploadAsync(stream, testFileName, true);
                    }

                    // Ignore errors if delete failed. User might not have delete permission and that won't affect normal operation. 
                    // It just means the file test file will need to be manually delete later.
                    sftp.DeleteFile(testFileName, ignoreFailures: true);
                    sftp.Disconnect();
                }
            }
            catch (InvalidOperationException)
            {
                throw new BadHttpRequestException("Invalid operation. This can happen if the passphrase is wrong.");
            }
            catch (Exception ex)
            {
                throw new BadHttpRequestException(ex.Message);
            }
        
        return true;
    }
}
