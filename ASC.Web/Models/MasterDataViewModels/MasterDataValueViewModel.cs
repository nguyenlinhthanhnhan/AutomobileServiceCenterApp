using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Models.MasterDataViewModels
{
    public class MasterDataValueViewModel
    {
        public string RowKey { get; set; }
        [Required]
        [Display(Name = "Partition Key")]
        public string PartitionKey { get; set; }
        public bool IsActive { get; set; }
        [Required]
        public string Name { get; set; }
    }
}
