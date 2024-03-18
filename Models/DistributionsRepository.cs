using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class DistributionsRepository : Repository<Distribution>
    {
        public int Add(int movieId, int distributorId)
        {
            Distribution distribution = new Distribution { MovieId = movieId, DistributorId = distributorId };
            return base.Add(distribution);
        }
        public bool Delete(int movieId, int distributorId)
        {
            Distribution distribution = DB.Distributions.ToList().Where(c => c.MovieId == movieId && c.DistributorId == distributorId).FirstOrDefault();
            if (distribution != null)
            {
                return base.Delete(distribution.Id);
            }
            return false;
        }
    }
}
