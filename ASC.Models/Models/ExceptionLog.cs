using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.Models
{
    public class ExceptionLog:BaseEntity
    {
        public ExceptionLog() { }
        public ExceptionLog(string key)
        {
            RowKey = Guid.NewGuid().ToString();
            PartitionKey = DateTime.UtcNow.ToString();
        }
        public string Message {get; set; }
        public string Stacktrace { get; set; }
    }
}
