using Microsoft.Extensions.Configuration;

namespace ApiForEncrypt.EncryptProvider
{
    public static class DecryptConfigurationExtensions
    {
        public static IConfigurationBuilder AddDecryptConfigurationBuilder(this IConfigurationBuilder builder)
        {
            return builder.Add(new DecryptConfigurationSource());
        }
    }
}
