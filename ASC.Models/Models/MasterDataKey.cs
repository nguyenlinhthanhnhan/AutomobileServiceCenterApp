using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.Models
{
    public class MasterDataKey:BaseEntity, IAuditTracker
    {
        public MasterDataKey() { }
        public MasterDataKey(string key)
        {
            PartitionKey = key;
        }
        public bool IsActive { get; set; }
        public string Name { get; set; }
    }
}
