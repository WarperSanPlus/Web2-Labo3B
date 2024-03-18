using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class Actor
    {
        const string Actor_Avatars_Folder = @"/Images_Data/Actor_Avatars/";
        const string Default_Avatar = @"no_avatar.png";
        public int Id { get; set; }

        [Required]
        [Display(Name = "Nom")]
        public string Name { get; set; }

        [Display(Name = "Avatar")]
        [ImageAsset(Actor_Avatars_Folder, Default_Avatar)]
        public string Avatar { get; set; } = Actor_Avatars_Folder + Default_Avatar;

        [Display(Name = "Date de naissance"), Required(ErrorMessage = "La date de naissance est requise")]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:yyyy-MM-dd}")]
        public DateTime BirthDate { get; set; }

        [Display(Name = "Nationalité")]
        public string CountryCode { get; set; }

        public bool AvatarSet()
        {
            return Avatar != Actor_Avatars_Folder + Default_Avatar;
        }
        [JsonIgnore]
        public List<Movie> Movies
        {
            get
            {
                List<Casting> castings = DB.Castings.ToList().Where(c => c.ActorId == Id).ToList();
                List<Movie> movies = new List<Movie>();
                foreach (var casting in castings)
                {
                    movies.Add(DB.Movies.Get(casting.MovieId));
                }
                return movies.OrderBy(c => c.Name).ToList();
            }
        }
        public SelectList MoviesToSeleclist()
        {
            return SelectListUtilities<Movie>.Convert(Movies);
        }
    }
}