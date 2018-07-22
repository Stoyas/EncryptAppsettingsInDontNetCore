using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;


namespace Starbucks.Payment.PayPalGateway.WebApi.ConfigProvider
{
    public class DecryptConfigurationSource : IConfigurationSource
    {
        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return new DecryptConfigProvider();
        }
    }
}
