using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class LoginCredential
    {
        [Display(Name = "Courriel"), EmailAddress(ErrorMessage = "Invalide"), Required(ErrorMessage = "Obligatoire")]
        [System.Web.Mvc.Remote("EmailExist", "Accounts", HttpMethod = "POST", ErrorMessage = "Courriel introuvable.")]
        public string Email { get; set; }

        [Display(Name = "Mot de passe"), Required(ErrorMessage = "Obligatoire")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [JsonIgnore]
        public int TimeZoneOffset { get; set; }
    }
}