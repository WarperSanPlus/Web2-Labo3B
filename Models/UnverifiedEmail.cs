using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MoviesDBManager.Models
{
    public class UnverifiedEmail
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string VerificationCode { get; set; }
        public int UserId { get; set; }
    }
}