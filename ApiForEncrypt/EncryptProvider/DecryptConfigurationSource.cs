using Microsoft.Extensions.Configuration;

namespace ApiForEncrypt.EncryptProvider
{
    public class DecryptConfigurationSource : IConfigurationSource
    {
        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return new DecryptConfigProvider();
        }
    }
}
