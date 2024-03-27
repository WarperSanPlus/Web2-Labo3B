using System.Collections.Generic;
using System.Web;
using System.Web.Mvc;

namespace MoviesDBManager.Models
{
    public static class OnlineUsers
    {
        private const string TAG_ONLINE_USERS = "OnLineUsers";

        private static List<int> ConnectedUsersId
        {
            get
            {
                if (HttpRuntime.Cache[TAG_ONLINE_USERS] == null)
                    HttpRuntime.Cache[TAG_ONLINE_USERS] = new List<int>();
                return (List<int>)HttpRuntime.Cache[TAG_ONLINE_USERS];
            }
        }

        /// <returns>Is the given id identified as a connected user</returns>
        public static bool IsOnline(int userId) => ConnectedUsersId.Contains(userId);

        private static bool hasChanged = false;

        /// <summary>
        /// Has changed since last call
        /// </summary>
        public static bool HasChanged
        {
            get
            {
                var saved = hasChanged;

                // Reset
                hasChanged = false;

                return saved;
            }
        }

        public static void AddSessionUser(int userId)
        {
            HttpContext.Current.Session["UserId"] = userId;

            // If the user is not online
            if (!IsOnline(userId))
            {
                // Add user from list
                ConnectedUsersId.Add(userId);

                // Update status
                hasChanged = true;
            }
        }
        public static void RemoveSessionUser()
        {
            // Get local user
            User currentUser = GetSessionUser();

            // If local user is set
            if (currentUser != null)
            {
                // Remove user from list
                _ = ConnectedUsersId.Remove(currentUser.Id);

                // Update status
                hasChanged = true;
            }

            HttpContext.Current?.Session.Abandon();
        }
        public static User GetSessionUser()
        {
            if (HttpContext.Current.Session["UserId"] != null)
            {
                User currentUser = DB.Users.Get((int)HttpContext.Current.Session["UserId"]);
                return currentUser;
            }

            return null;
        }
        public static bool Write_Access()
        {
            User sessionUser = OnlineUsers.GetSessionUser();
            return sessionUser != null && (sessionUser.IsPowerUser || sessionUser.IsAdmin);
        }

        public class UserAccess : AuthorizeAttribute
        {
            protected override bool AuthorizeCore(HttpContextBase httpContext)
            {
                User sessionUser = OnlineUsers.GetSessionUser();
                if (sessionUser != null)
                {
                    if (sessionUser.Blocked)
                    {
                        RemoveSessionUser();
                        httpContext.Response.Redirect("~/Accounts/Login?message=Compte bloqué!");
                        return false;
                    }

                    return true;
                }

                httpContext.Response.Redirect("~/Accounts/Login?message=Accès non autorisé!");
                return false;

            }
        }
        public class PowerUserAccess : AuthorizeAttribute
        {
            protected override bool AuthorizeCore(HttpContextBase httpContext)
            {
                User sessionUser = OnlineUsers.GetSessionUser();
                if (sessionUser != null && (sessionUser.IsPowerUser || sessionUser.IsAdmin))
                {
                    return true;
                }
                else
                {
                    RemoveSessionUser();
                    httpContext.Response.Redirect("~/Accounts/Login?message=Accès non autorisé!", true);
                }

                return false;
            }
        }
        public class AdminAccess : AuthorizeAttribute
        {
            protected override bool AuthorizeCore(HttpContextBase httpContext)
            {
                User sessionUser = OnlineUsers.GetSessionUser();
                if (sessionUser != null && sessionUser.IsAdmin)
                {
                    return true;
                }
                else
                {
                    RemoveSessionUser();
                    httpContext.Response.Redirect("~/Accounts/Login?message=Accès non autorisé!");
                }

                return true;
            }
        }
    }
}