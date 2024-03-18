using Antlr.Runtime.Misc;
using MoviesDBManager.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace MoviesDBManager.Controllers
{
    [OnlineUsers.UserAccess]
    public class DistributorsController : Controller
    {
        public ActionResult Index()
        {
            Session["LastAction"] = "/Distributors/index";
            return View();
        }
        public PartialViewResult Distributors(bool forceRefresh = false)
        {
            if (forceRefresh || DB.Distributors.HasChanged)
            {
                return PartialView(DB.Distributors.ToList().OrderBy(c => c.Name));
            }
            return null;
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Create()
        {
            return View(new Distributor());
        }
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Create(Distributor distributor, List<int> SelectedMoviesId)
        {
            if (ModelState.IsValid)
            {
                DB.Distributors.Add(distributor);
                return RedirectToAction("Index");
            }
            return View();
        }
        public ActionResult Details(int id)
        {
            Session["LastAction"] = "/Distributors/Details/" + id;
            Distributor distributor = DB.Distributors.Get(id);
            if (distributor != null)
            {
                Session["CurrentDistributorId"] = distributor.Id;
                return View(distributor);
            }
            return RedirectToAction("Index");
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Edit()
        {
            if (Session["CurrentDistributorId"] != null)
            {
                Distributor distributor = DB.Distributors.Get((int)Session["CurrentDistributorId"]);
                if (distributor != null)
                {
                    return View(distributor);
                }
            }
                return RedirectToAction("Index");
        }
        [HttpPost]
        [ValidateAntiForgeryToken()]
        public ActionResult Edit(Distributor distributor, List<int> SelectedMovies)
        {
            distributor.Id = (int)Session["CurrentDistributorId"];
            if (ModelState.IsValid)
            {
                DB.Distributors.Update(distributor, SelectedMovies);
                Session["CurrentDistributorId"] = null;
                return Redirect((string)Session["LastAction"]);
            }
            return View(distributor);
        }
        [OnlineUsers.PowerUserAccess]
        public ActionResult Delete()
        {
            if (Session["CurrentDistributorId"] != null)
            {
                DB.Distributors.Delete((int)Session["CurrentDistributorId"]);
                Session["CurrentDistributorId"] = null;
            }
            return RedirectToAction("Index");
        }
    }
}