using System;
using System.ComponentModel.DataAnnotations;

namespace WEF.Models
{
    public partial class GeneralEvents
    {
        [Display(Name = "Event ID")]
        public int? Id { get; set; }
        [Display(Name = "Log Level")]
        public string LevelDisplayName { get; set; }
        [Display(Name = "Log Name")]
        public string LogName { get; set; }
        [Display(Name = "Device Name")]
        public string MachineName { get; set; }
        [Display(Name = "Message")]
        public string Message { get; set; }
        [Display(Name = "Provider Name")]
        public string ProviderName { get; set; }
        [Display(Name = "Record ID")]
        public long? RecordId { get; set; }
        [Display(Name = "Task Display Name")]
        public string TaskDisplayName { get; set; }
        [Display(Name = "Time Created")]
        public DateTime? TimeCreated { get; set; }
    }
}
