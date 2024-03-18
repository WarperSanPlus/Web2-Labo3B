using Newtonsoft.Json;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class Distributor
    {
        const string Distributor_Logos_Folder = @"/Images_Data/Distributor_Logos/";
        const string Default_Distributor_Logo = @"No_Logo.png";

        public int Id { get; set; }
        [Required]
        [Display(Name = "Distributeur")]
        public string Name { get; set; }

        [ImageAsset(Distributor_Logos_Folder, Default_Distributor_Logo)]
        public string Logo{ get; set; } = Distributor_Logos_Folder + Default_Distributor_Logo;

        [Display(Name = "Pays")]
        public string CountryCode { get; set; }

        [JsonIgnore]
        public List<Movie> Movies
        {
            get
            {
                List<Distribution> distributions = DB.Distributions.ToList().Where(c => c.DistributorId == Id).ToList();
                List<Movie> movies = new List<Movie>();
                foreach (var distribution in distributions)
                {
                    movies.Add(DB.Movies.Get(distribution.MovieId));
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