using Azure.Identity;
using Microsoft.Extensions.Azure;
using KeyVaultSampleApp.Interfaces.KeyVault;
using KeyVaultSampleApp.Interfaces.SSH;
using KeyVaultSampleApp.Services.KeyVault;
using KeyVaultSampleApp.Services.SSH;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Add services to the container.
var keyVaultSettings = config.GetSection(nameof(KeyVaultSettings)).Get<KeyVaultSettings>();
builder.Configuration.AddAzureKeyVault(keyVaultSettings.VaultUri, new ClientSecretCredential(keyVaultSettings.TenantId, keyVaultSettings.KeyId, keyVaultSettings.ClientSecret)); 

builder.Services.AddAzureClients(azureClientFactoryBuilder => {
            azureClientFactoryBuilder.AddKeyClient(config.GetSection(nameof(KeyVaultSettings)));
            azureClientFactoryBuilder.AddSecretClient(config.GetSection(nameof(KeyVaultSettings)));
            azureClientFactoryBuilder.AddCryptographyClient(keyVaultSettings.VaultUri);
        });
builder.Services.AddSingleton<IKeyVaultClient, KeyVaultClientWrapper>();
builder.Services.AddSingleton<ISftpClientFactory, SftpClientFactory>();


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
