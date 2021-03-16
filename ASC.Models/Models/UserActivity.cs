using ASC.Models.BaseTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.Models
{
    public class UserActivity:BaseEntity
    {
        public UserActivity() { }
        public UserActivity(string email)
        {
            RowKey = Guid.NewGuid().ToString();
            PartitionKey = email;
        }
        public string Action { get; set; }
    }
}
