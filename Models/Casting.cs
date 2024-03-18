using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class Casting
    {
        public int Id { get; set; }
        public int MovieId { get; set; }
        public int ActorId { get; set; }
    }
}