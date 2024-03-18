using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class User
    {
        public const string User_Avatars_Folder = @"/Images_Data/User_Avatars/";
        public const string Default_Avatar = @"no_avatar.png";

        [JsonIgnore]
        public static string DefaultImage {  get { return User_Avatars_Folder + Default_Avatar; } }

        public User Clone()
        {
            return JsonConvert.DeserializeObject<User>(JsonConvert.SerializeObject(this));
        }
        #region Data Members
        public int Id { get; set; } = 0;
        public int UserTypeId { get; set; } = 3;
        public bool Verified { get; set; } = false;
        public bool Blocked { get; set; } = false;

        [Display(Name = "Prenom"), Required(ErrorMessage = "Obligatoire")]
        public string FirstName { get; set; }

        [Display(Name = "Nom"), Required(ErrorMessage = "Obligatoire")]
        public string LastName { get; set; }

        [Display(Name = "Désignation"), Required(ErrorMessage = "Obligatoire")]
        public int GenderId { get; set; }

        [Display(Name = "Courriel"), EmailAddress(ErrorMessage = "Invalide"), Required(ErrorMessage = "Obligatoire")]
        [System.Web.Mvc.Remote("EmailAvailable", "Accounts", HttpMethod = "POST", AdditionalFields = "Id", ErrorMessage = "Ce courriel n'est pas disponible.")]
        public string Email { get; set; }

        [Display(Name = "Avatar")]
        [ImageAsset(User_Avatars_Folder, Default_Avatar)]
        public string Avatar { get; set; } = DefaultImage;

        [Display(Name = "Mot de passe"), Required(ErrorMessage = "Obligatoire")]
        [StringLength(50, ErrorMessage = "Le mot de passe doit comporter au moins {2} caractères.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public String Password { get; set; }

        [JsonIgnore]
        [Display(Name = "Confirmation")]
        [Compare("Email", ErrorMessage = "Le courriel et celui de confirmation ne correspondent pas.")]
        public string ConfirmEmail { get; set; }

        [JsonIgnore]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmation")]
        [Compare("Password", ErrorMessage = "Le mot de passe et celui de confirmation ne correspondent pas.")]
        public string ConfirmPassword { get; set; }

        [Display(Name = "Date de création")]
        [DataType(DataType.Date)]
        public DateTime CreationDate { get; set; } = DateTime.Now;
        #endregion
        #region View members

        [JsonIgnore]
        public Gender Gender { get { return DB.Genders.Get(GenderId); } }
        [JsonIgnore]
        public UserType UserType { get { return DB.UserTypes.Get(UserTypeId); } }
        [JsonIgnore]
        public bool IsPowerUser { get { return UserTypeId <= 2 /* Admin = 1 , PowerUser = 2 */; } }
        [JsonIgnore]
        public bool IsAdmin { get { return UserTypeId == 1 /* Admin */; } }

        public string GetFullName(bool showGender = false)
        {
            if (showGender)
            {
                if (Gender.Name != "Neutre")
                    return Gender.Name + " " + LastName;
            }
            return FirstName + " " + LastName;
        }
        #endregion
    }

}