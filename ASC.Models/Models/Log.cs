using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.Models
{
    public class Log:BaseEntity
    {
        public Log() { }
        public Log(string key)
        {
            RowKey = Guid.NewGuid().ToString();
            PartitionKey = key;
        }
        public string Message { get; set; }
    }
}
