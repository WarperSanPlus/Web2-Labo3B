using Newtonsoft.Json;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class Movie
    {
        const string Movie_Posters_Folder = @"/Images_Data/Movie_Posters/";
        const string Default_Movie_Poster = @"no_poster.png";

        public int Id { get; set; }
        [Required(ErrorMessage = "Le titre est requis")]
        [Display(Name = "Titre")]
        public string Name { get; set; }

        [Required(ErrorMessage = "L'année de sortie est requise")]
        [Display(Name = "Année de sortie")]
        [Range(1930, 2099, ErrorMessage = "Valeur pour {0} doit être entre {1} et {2}.")]
        public int ReleaseYear { get; set; }

        [Display(Name = "Pays")]
        public string CountryCode { get; set; }

        [Required(ErrorMessage = "Le synopsis est requis")]
        [Display(Name = "Synopsis")]
        [DataType(DataType.MultilineText)]
        public string Synopsis { get; set; }

        [Display(Name = "Affiche")]
        [ImageAsset(Movie_Posters_Folder, Default_Movie_Poster)]
        public string Poster { get; set; } = Movie_Posters_Folder + Default_Movie_Poster;

        [JsonIgnore]
        public List<Actor> Actors
        {
            get
            {
                List<Casting> castings = DB.Castings.ToList().Where(c => c.MovieId == Id).ToList();
                List<Actor> actors = new List<Actor>();
                foreach (var casting in castings)
                {
                    actors.Add(DB.Actors.Get(casting.ActorId));
                }
                return actors.OrderBy(c => c.Name).ToList();
            }
        }
        [JsonIgnore]
        public List<Distributor> Distributors
        {
            get
            {
                List<Distribution> distributions = DB.Distributions.ToList().Where(c => c.MovieId == Id).ToList();
                List<Distributor> distributors = new List<Distributor>();
                foreach (var casting in distributions)
                {
                    distributors.Add(DB.Distributors.Get(casting.DistributorId));
                }
                return distributors.OrderBy(c => c.Name).ToList();
            }
        }
        public SelectList ActorsToSeleclist()
        {
            return SelectListUtilities<Actor>.Convert(Actors);
        }
        public SelectList DistributorsToSeleclist()
        {
            return SelectListUtilities<Distributor>.Convert(Distributors);
        }
    }
}