using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public class DistributorsRepository : Repository<Distributor>
    {
        public SelectList ToSelectList()
        {
            return SelectListUtilities<Distributor>.Convert(ToList().OrderBy(m => m.Name));
        }
        private void UpdateDistribution(Distributor distributor, List<int> moviesId)
        {
            DeleteDistributions(distributor);
            if (moviesId != null && moviesId.Count > 0)
            {
                foreach (var movieId in moviesId)
                {
                    DB.Distributions.Add(movieId, distributor.Id);
                }
            }
        }
        private void DeleteDistributions(Distributor distributor)
        {
            foreach (var movie in distributor.Movies)
            {
                DB.Distributions.Delete(movie.Id, distributor.Id);
            }
        }
        public bool Update(Distributor distributor, List<int> moviesId)
        {
            BeginTransaction();
            base.Update(distributor);
            UpdateDistribution(distributor, moviesId);
            EndTransaction();
            return true;
        }
        public override bool Delete(int Id)
        {
            BeginTransaction();
            Distributor distributor = Get(Id);
            if (distributor != null)
            {
                DeleteDistributions(distributor);
                base.Delete(Id);
            }
            EndTransaction();
            return true;
        }
    }
}