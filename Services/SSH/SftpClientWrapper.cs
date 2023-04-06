using System.Net.Sockets;
using Renci.SshNet;
using Renci.SshNet.Common;
using System.Security.Cryptography;
using KeyVaultSampleApp.Interfaces.SSH;
using KeyVaultSampleApp.Models;

namespace KeyVaultSampleApp.Services.SSH;

public class SftpClientWrapper : IDisposable, KeyVaultSampleApp.Interfaces.SSH.ISftpClient
    {
        private readonly SftpClient _sftp;
        public string HostKeyFingerPrint = string.Empty;

        public static SftpClientWrapper Create(FtpSettings settings)
        {
            return new SftpClientWrapper(settings);
        }

        private SftpClientWrapper(FtpSettings settings)
        {
            if (settings.AllowPrivateKeyAuthentication == true)
            {
                var connInfo = GetSftpConnection(settings);
                _sftp = new SftpClient(connInfo);
            }
            else
            {
                var connInfo = new Renci.SshNet.ConnectionInfo(settings.Server, settings.Port, settings.UserName, new PasswordAuthenticationMethod(settings.UserName, settings.Password));
                _sftp = new SftpClient(connInfo);
            }
        }

        public void ChangeDirectory(string path)
        {
            try
            {
                _sftp.ChangeDirectory(path);
                if (_sftp.WorkingDirectory != path)
                {
                    throw new Exception("Failed to change directory due to unknown reasons.");
                }
            }
            catch (SftpPermissionDeniedException ex)
            {
                throw new Exception("Directory permission denied.", ex);
            }
            catch (SftpPathNotFoundException ex)
            {
                throw new Exception("Directory not found.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error has occurred: " + ex.Message, ex);
            }
        }

        public void Connect()
        {
            try
            {
                _sftp.HostKeyReceived += delegate (object sender, HostKeyEventArgs e)
                {
                    HostKeyFingerPrint = Convert.ToBase64String(new SHA256Managed().ComputeHash(e.HostKey));
                };

                if (!_sftp.IsConnected)
                {
                    _sftp.Connect();
                }

                if (!_sftp.IsConnected)
                {
                    throw new Exception("Failed to connect due to unknown reasons.");
                }
            }
            catch (SocketException ex)
            {
                throw new Exception("Connection to the server could not be established. Please check that the Server and Port provided are correct.", ex);
            }
            catch (SshConnectionException ex)
            {
                throw new Exception("Connection to the server could not be established.", ex);
            }
            catch (SshAuthenticationException ex)
            {
                throw new Exception("Authentication failed.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error has occurred: " + ex.Message, ex);
            }
        }

        public string GetHostKeyFingerPrints()
        {
            return HostKeyFingerPrint;
        }

        public async Task UploadAsync(Stream stream, string filename, bool canOverride)
        {
            try
            {
                CreateDirectoryRecursively(filename);
                await _sftp.UploadAsync(stream, filename, canOverride);
            }
            catch (SftpPathNotFoundException ex)
            {
                throw new Exception("Invalid upload path.", ex);
            }
            catch (SftpPermissionDeniedException ex)
            {
                throw new Exception("Permission denied", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error has occurred: " + ex.Message, ex);
            }
        }

        public void DeleteFile(string filename, bool ignoreFailures = false)
        {
            try
            {
                _sftp.DeleteFile(filename);
            }
            catch (SftpPathNotFoundException ex)
            {
                if (!ignoreFailures)
                {
                    throw new Exception("File not found.", ex);
                }
            }
            catch (SftpPermissionDeniedException ex)
            {
                if (!ignoreFailures)
                {
                    throw new Exception("Permission denied.", ex);
                }
            }
            catch (Exception ex)
            {
                if (!ignoreFailures)
                {
                    throw new Exception("An unexpected error has occurred: " + ex.Message, ex);
                }
            }
        }

        public void Disconnect()
        {
            try
            {
                _sftp.Disconnect();
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error has occurred: " + ex.Message, ex);
            }
        }

        protected void CreateDirectoryRecursively(string path)
        {
            string current = _sftp.WorkingDirectory;

            if (path[0] == '/')
            {
                path = path.Substring(1);
            }

            var folders = path.Split('/');

            if (folders.Length == 1)
                return;

            for(var i = 0; i < folders.Length - 1; ++i)
            {
                current += "/" + folders[i];

                if (_sftp.Exists(current))
                {
                    var attrs = _sftp.GetAttributes(current);
                    if (!attrs.IsDirectory)
                    {
                        throw new Exception("not directory");
                    }
                }
                else
                {
                    _sftp.CreateDirectory(current);
                }
            }
        }

        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed && disposing)
            {
                // Clean up
                _sftp?.Dispose();

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private static Renci.SshNet.ConnectionInfo GetSftpConnection(FtpSettings ftpSettings)
        {
            return new Renci.SshNet.ConnectionInfo(ftpSettings.Server, ftpSettings.Port, ftpSettings.UserName, PrivateKeyObject(ftpSettings));
        }
        private static AuthenticationMethod[] PrivateKeyObject(FtpSettings ftpSettings)
        {
            PrivateKeyFile privateKeyFile = new PrivateKeyFile(new MemoryStream(ftpSettings.PrivateKeyContent), ftpSettings.PassPhrase);
            PrivateKeyAuthenticationMethod privateKeyAuthenticationMethod =
                 new PrivateKeyAuthenticationMethod(ftpSettings.UserName, privateKeyFile);
            return new AuthenticationMethod[] { privateKeyAuthenticationMethod };
        }
    }