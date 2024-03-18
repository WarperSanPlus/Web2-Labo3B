using MoviesDBManager.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MoviesDBManager.Controllers
{
    [OnlineUsers.UserAccess]
    public class MoviesController : Controller
    {
        public ActionResult Index()
        {
            Session["LastAction"] = "/Movies/index";
            return View();
        }
        public ActionResult Movies(bool forceRefresh = false)
        {
            if (forceRefresh || DB.Movies.HasChanged)
            {
                return PartialView(DB.Movies.ToList().OrderBy(c => c.Name));
            }
            return null;
        }

        [OnlineUsers.PowerUserAccess]
        public ActionResult Create()
        {
            return View(new Movie());
        }

        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Create(Movie movie, List<int> SelectedActors, List<int> SelectedDistributorsId)
        {
            if (ModelState.IsValid)
            {
                DB.Movies.Add(movie);
                return RedirectToAction("Index");
            }
            return View();
        }
        public ActionResult Details(int id)
        {
            Session["LastAction"] = "/Movies/Details/" + id;
            Movie movie = DB.Movies.Get(id);
            if (movie != null)
            {
                Session["CurrentMovieId"] = movie.Id;
                return View(movie);
            }
            return RedirectToAction("Index");
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Edit()
        {
            if (Session["CurrentMovieId"] != null)
            {
                Movie movie = DB.Movies.Get((int)Session["CurrentMovieId"]);
                if (movie != null)
                {
                    return View(movie);
                }
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Edit(Movie movie, List<int> SelectedActors, List<int> SelectedDistributors)
        {
            movie.Id = (int)Session["CurrentMovieId"];
            if (ModelState.IsValid)
            {
                DB.Movies.Update(movie, SelectedActors, SelectedDistributors);
                Session["CurrentMovieId"] = null;
                return Redirect((string)Session["LastAction"]);
            }
            return View();
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Delete()
        {
            if (Session["CurrentMovieId"] != null)
            {
                DB.Movies.Delete((int)Session["CurrentMovieId"]);
                Session["CurrentMovieId"] = null;
            }
            return RedirectToAction("Index");
        }
    }
}