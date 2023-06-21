using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    public class IndexController : Controller
    {
        // GET: Index
        public ActionResult IndexPage()
        {
            return View("Index");
        }

    }
}
