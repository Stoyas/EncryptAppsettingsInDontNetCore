using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace Starbucks.Payment.PayPalGateway.WebApi.ConfigProvider
{
    public static class DecryptConfigurationExtensions
    {
        public static IConfigurationBuilder AddDecryptConfigurationBuilder(this IConfigurationBuilder builder)
        {
            return builder.Add(new DecryptConfigurationSource());
        }
    }
}
