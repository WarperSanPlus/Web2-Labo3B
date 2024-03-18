using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class ActorsRepository : Repository<Actor>
    {
        public SelectList ToSelectList()
        {
            return SelectListUtilities<Actor>.Convert(ToList().OrderBy(m => m.Name));
        }
        private void UpdateCasting(Actor actor, List<int> moviesId)
        {
            DeleteCastings(actor);
            if (moviesId != null && moviesId.Count > 0)
            {
                foreach (var movieId in moviesId)
                {
                    DB.Castings.Add(movieId, actor.Id);
                }
            }
        }
        private void DeleteCastings(Actor actor)
        {
            foreach (var movie in actor.Movies)
            {
                DB.Castings.Delete(movie.Id, actor.Id);
            }
        }
        public bool Update(Actor actor, List<int> moviesId)
        {
            BeginTransaction(); 
            base.Update(actor);
            UpdateCasting(actor, moviesId);
            EndTransaction();
            return true;
        }
        public override bool Delete(int Id)
        {
            BeginTransaction();
            Actor actor = Get(Id);
            if (actor != null)
            {
                DeleteCastings(actor);
                base.Delete(Id);
            }
            EndTransaction();
            return true;
        }
    }
}