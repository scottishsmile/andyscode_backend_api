using System.Collections.Generic;

namespace API
{
    public class Constants
    {
        // Keep all constant variables here and access them throughout the app.
        // This avoids "Magic Numbers", numbers dotted throughout the app that you don't know.

        public static class Defaults
        {
            public const bool MY_SETTING = true;
            public const int EMAIL_COMPARE_TIME = 5;        // How often should we resend an email? In minutes. Stops spammers hitting the request new password email 1000 times.
        }


        public static class Admin
        {
            public const int maxRows = 50;                  // Used in GetPagedUsers. For paging. Batches of 50 records per page. 
        }

        public static class HrefLinks
        {
            // So we can update the links on the razor view pages.
            // For the confirm email, reset password web pages.

            public const string mainUrl = "https://localhost:7008/";
            public const string frontEndUrl = "https://localhost:3000";
            public const string frontEndUrl_ResetPassword = "https://localhost:3000/members/forgotpass";
            public const string frontEndUrl_Contact = "https://localhost:3000/members/contact";
        }

        public static class Cors
        {
            // Http and Https of front-end website
            public static string[] urls = { "http://localhost:3000", "https://localhost:3000" };        // Should maybe be in appsettings instead? User will need to configure it, may as well have it all in one place.
        }

    }
}


/*
The class you want to use constants in:
---------------------------------------
 

using static API.Constants;

		
		
bool mySetting = Defaults.MY_SETTING;






The Constants.cs class:
-----------------------


using System.Collections.Generic;

namespace API.Services
{
    public static class Constants
    {
        public static class Defaults
        {
	        public const string MY_SETTING = true;
        }
    }
}




Unit Tests:
-----------

// Arrange
var myTestSetting = new ConfigProperty()
{
    Key = Defaults.MY_SETTING,
    Value = true.ToString()       
};
 
_mockConfigManager.Setup(mk => mk.Get(Defaults.MY_SETTING)).Returns(Task.FromResult(myTestSetting));


*/