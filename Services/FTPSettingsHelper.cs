using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using KeyVaultSampleApp.Models;

namespace KeyVaultSampleApp.Services;
public class FTPSettingsHelper
{
    private static readonly Regex PrivateKeyRegex = new Regex(@"^-+ *BEGIN (?<keyName>\w+( \w+)*) PRIVATE KEY *-+\r?\n((Proc-Type: 4,ENCRYPTED\r?\nDEK-Info: (?<cipherName>[A-Z0-9-]+),(?<salt>[A-F0-9]+)\r?\n\r?\n)|(Comment: ""?[^\r\n]*""?\r?\n))?(?<data>([a-zA-Z0-9/+=]{1,80}\r?\n)+)-+ *END \k<keyName> PRIVATE KEY *-+",
        #if SILVERLIGHT
            RegexOptions.Multiline);
        #else
            RegexOptions.Compiled | RegexOptions.Multiline);
    #endif

    public static FtpSettings GetPrivateKey(IFormFileCollection files, FtpSettings ftpSettings)
    {
        if (files != null && files.Count > 0)
        {
            var inputStream = new MemoryStream();
            var privateKey = files.GetFile("privateKey");
            if (privateKey != null)
            {
                privateKey.CopyToAsync(inputStream);
                ftpSettings.PrivateKeyContent = new byte[inputStream.Length];
                inputStream.Read(ftpSettings.PrivateKeyContent, 0, (int)inputStream.Length);
            }
        }
        return ftpSettings;
    }

    public static Tuple<bool, string> ValidatePostData(FtpSettings inputFtpSettings)
    {
        if (inputFtpSettings.AllowPrivateKeyAuthentication != true && string.IsNullOrWhiteSpace(inputFtpSettings.Password))
        {
            return new Tuple<bool, string>(false, "Password is required");
        }

        if (inputFtpSettings.AllowPrivateKeyAuthentication == true &&
                            (inputFtpSettings.PrivateKeyContent == null ||
                            inputFtpSettings.PrivateKeyContent.Length <= 0))
        {
            return new Tuple<bool, string>(false, "Private key is required");
        }

        if (inputFtpSettings.PrivateKeyContent != null)
        {
            var isValid = ValidatePrivateKeyFile(inputFtpSettings.PrivateKeyContent);

            if (!isValid)
            {
                return new Tuple<bool, string>(false, "Invalid private key file");
            }
        }

        return new Tuple<bool, string>(true, string.Empty);
    }

    private static bool ValidatePrivateKeyFile(byte[] privateKey)
    {
        Match privateKeyMatch;
        using (var sr = new StreamReader(new MemoryStream(privateKey)))
        {
            var text = sr.ReadToEnd();
            privateKeyMatch = PrivateKeyRegex.Match(text);
        }

        if (!privateKeyMatch.Success)
        {
            return false;
        }

        return true;
    }
}