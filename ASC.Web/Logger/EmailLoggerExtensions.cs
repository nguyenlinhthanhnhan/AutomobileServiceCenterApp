using ASC.Business.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Logger
{
    public static class EmailLoggerExtensions
    {
        public static ILoggerFactory AddAzureTableStorageLog(this ILoggerFactory factory,
                                                             ILogDataOperations logDataOperations,
                                                             Func<string, LogLevel, bool> filter = null)
        {
            factory.AddProvider(new AzureStorageLoggerProvider(filter, logDataOperations));
            return factory;
        }
    }
}
