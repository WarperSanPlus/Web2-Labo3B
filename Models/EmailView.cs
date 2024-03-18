using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class EmailView
    {
        [Display(Name = "Courriel"), EmailAddress(ErrorMessage = "Invalide"), Required(ErrorMessage = "Obligatoire")]
        [Remote("EmailExist", "Accounts", HttpMethod = "POST", ErrorMessage = "Courriel introuvable.")]
        public string Email { get; set; }
    }
}