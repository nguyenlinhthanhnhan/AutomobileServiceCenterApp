using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.Models
{
    public class MasterDataValue:BaseEntity, IAuditTracker
    {
        public MasterDataValue() { }
        public MasterDataValue(string masterDataPartitionKey, string value)
        {
            PartitionKey = masterDataPartitionKey;
        }
        public bool IsActive { get; set; }
        public string Name { get; set; }
    }
}
