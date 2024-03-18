using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MoviesDBManager.Models;

namespace MoviesDBManager.Controllers
{
    [OnlineUsers.UserAccess]
    public class ActorsController : Controller
    {
        public ActionResult Index()
        {
            Session["LastAction"] = "/Actors/index";
            return View();
        }
        public ActionResult Actors(bool forceRefresh = false)
        {
            if (forceRefresh || DB.Actors.HasChanged)
            {
                return PartialView(DB.Actors.ToList().OrderBy(c => c.Name));
            }
            return null;
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Create()
        {
            return View(new Actor());
        }
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Create(Actor actor, List<int> SelectedMovies)
        {
            if (ModelState.IsValid)
            {
                DB.Actors.Add(actor);
                return RedirectToAction("Index");
            }
            return View();
        }
        public ActionResult Details(int id)
        {
            Session["LastAction"] = "/Actors/Details/" + id;
            Actor actor = DB.Actors.Get(id);
            if (actor != null)
            {
                Session["CurrentActorId"] = actor.Id;
                return View(actor);
            }
            Session["CurrentActorId"] = null;
            return RedirectToAction("Index");
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Edit()
        {
            if (Session["CurrentActorId"] != null)
            {
                Actor actor = DB.Actors.Get((int)Session["CurrentActorId"]);
                if (actor != null)
                {
                    return View(actor);
                }
            }
            return RedirectToAction("Index");
        }
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Edit(Actor actor, List<int> SelectedMovies)
        {
            actor.Id = (int)Session["CurrentActorId"];
            if (ModelState.IsValid)
            {
                DB.Actors.Update(actor, SelectedMovies);
                Session["CurrentActorId"] = null;
                return Redirect((string)Session["LastAction"]);
            }
            return View(actor);
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Delete()
        {
            if (Session["CurrentActorId"] != null)
            {
                DB.Actors.Delete((int)Session["CurrentActorId"]);
                Session["CurrentActorId"] = null;
            }
            return RedirectToAction("Index");
        }
    }
}