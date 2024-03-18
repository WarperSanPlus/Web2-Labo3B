using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class CastingsRepository : Repository<Casting>
    {
        public int Add(int movieId, int actorId)
        {
            Casting casting = new Casting { MovieId = movieId , ActorId = actorId };
            return base.Add(casting);
        }
        public bool Delete(int movieId, int actorId)
        {
            Casting casting = DB.Castings.ToList().Where(c => c.MovieId == movieId && c.ActorId == actorId).FirstOrDefault();
            if (casting != null)
            {
                return base.Delete(casting.Id);
            }
            return false;
        }
    }
}