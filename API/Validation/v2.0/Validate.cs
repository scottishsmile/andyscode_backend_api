using System.Diagnostics;
using System.Text.RegularExpressions;

namespace API.Validation.v2_0
{

    public class ValidateV2 : IValidateV2
    {

        private readonly ILogger<ValidateV2> _logger;

        // Constructor
        public ValidateV2(ILogger<ValidateV2> logger)
        {

            _logger = logger;
        }

        // Blacklists
        // It's much better to have a whitelist of only allowing certain user behaviour.
        // However, that's not possible here as a user can enter a wide number of inputs for a username, email or password.
        // The "badWords" list is a blacklist of known sql commands we don't want to allow.
        // Words like "add" and "char" will sometimes blacklist good behaviour like the names "mADDy" and "CHARlie". "Grant" is also a name and a sql command.

        // Parameterised queries
        // This blacklist should be used with parameterised queries in the SQL CRUD commands.
        // Parameterised queries don't allow user input to be sent as text, it's sent as parameters which stops any commands running.
        // Easily spotted by the @ symbol.
        //      string sql = "select ALL from MyTable where UserID=@UserID and pwd=@pwd";
        // Linq/Entity framework uses parameterised queries.


        // A list of bad words and SQL symbols that could be used in an SQL injection attack.
        // Also includes XSS scripting keywords, for injecting html and javascript into the page.
        List<string> badWords = new List<string>()
        { 
            // Passwords, Usernames (and now email addresses RFC 5322) may contain special characters !@#$%^&*()
            // SQL commands
            " add ",      // Add is a difficult one. Can't be "add" or it will match Maddy, need to include spaces.
            "add ",
            "alert ",
            "alter ",
            "begin ",
            "body ",
            "cast ",
            "char ",
            "checkpoint ",
            "click ",
            "cookie ",
            "commit ",
            "create ",
            "cursor ",
            "database ",
            "delete ",
            "describe ",
            "deny ",
            "document ",
            "drop ",
            "error ",
            "exec ",
            "execute ",
            "focus ",
            "footer ",
            "fetch ",
            "from ",
            "form ",
            "grant ",
            " grant",
            "group ",
            "header ",
            "href ",
            "html ",
            "img ",
            "index ",
            "inner ",
            "insert ",
            "json ",
            "join ",
            "kill ",
            "like ",
            " like",
            "link ",
            "limit ",
            "load ",
            "localhost ",
            "null ",
            "onmouse ",
            "onload ",
            "onchange ",
            "open ",
            "order ",
            "outer ",
            "password ",
            "replace ",
            "rollback ",
            "savepoint ",
            "script ",
            "select ",
            "section ",
            "set ",
            "show ",
            "string ",
            "storage ",
            "submit ",
            "svg ",
            "table ",
            "then ",
            "truncate ",
            "update ",
            "use ",
            "value ",
            "where ",
            ".css ",
            ".exe ",
            ".htm ",
            ".js ",
            ".ps ",
            ".py ",
            "fuck ",         // Swears
            "shit ",
            "cunt ",
            "bitch ",
            "whore ",
            "slut ",
            "bastard ",
        };

        // JWT Tokens have long randomly generated strings "CfR56$32..."etc
        // They may randomly generate some of the bad words! So our validation may deny a valid token.
        // A space was added after every word, no jwt token should have a space.
        List<string> jwtTokenBadWords = new List<string>()
        {
            "add ",
            "alert ",
            "alter ",
            "begin ",
            "body ",
            "cast ",
            "char ",
            "checkpoint ",
            "click ",
            "cookie ",
            "commit ",
            "create ",
            "cursor ",
            "database ",
            "delete ",
            "describe ",
            "deny ",
            "document ",
            "drop ",
            "error ",
            "exec ",
            "execute ",
            "focus ",
            "footer ",
            "fetch ",
            "from ",
            "form ",
            "grant ",
            "group ",
            "header ",
            "href ",
            "html ",
            "img ",
            "index ",
            "inner ",
            "insert ",
            "json ",
            "join ",
            "kill ",
            "like ",
            "link ",
            "limit ",
            "load ",
            "localhost ",
            "null ",
            "onmouse ",
            "onload ",
            "onchange ",
            "open ",
            "order ",
            "outer ",
            "password ",
            "replace ",
            "rollback ",
            "savepoint ",
            "script ",
            "select ",
            "section ",
            "set ",
            "show ",
            "string ",
            "storage ",
            "submit ",
            "svg ",
            "table ",
            "then ",
            "truncate ",
            "update ",
            "use ",
            "value ",
            "where ",
            ".css ",
            ".exe ",
            ".htm ",
            ".js ",
            ".ps ",
            ".py ",
        };



        // Validates fields that should only contain alphabet charcacters
        public int alphabetValidation(string userInput)
        {
            try
            {
                int answer = 0;

                // Check for null or blank input.
                if (!String.IsNullOrEmpty(userInput))
                {


                    // Check length
                    // Allowing a long query opens up space for SQL injection attacks.
                    if (userInput.Length > 70)
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - alphabetValidation - Input was greater than 70 characters or was null");
                        _logger.LogWarning("Validation failed at - alphabetValidation - Input was greater than 70 characters or was null");
                    }

                    /*
                     * No Need to check for characters only, username can be characters and numbers.
                     * 
                    // Check for characters only

                    // Regex
                    // ^ = start at beginning of the string
                    // [a-zA-Z] = match any letters lowercase a-z or Uppercase A-Z
                    // + = match more than once occurence of this
                    // A space is \s. Needed for street names "Main St" and middle names "David John"
                    // ? = optional match. the first group of letters need to be matched but the space and the second group are optional
                    // $ = end of the string

                    if (Regex.IsMatch(userInput, @"^[a-zA-Z]+\s?[a-zA-Z]+$"))
                    {

                        Console.WriteLine(String.Format("Regex Validation Passed...." + userInput), "Info");
                    }
                    else
                    {
                        Console.WriteLine(String.Format("Regex Validation Failed. Input is not only characters..." + userInput), "Error");
                        answer = answer + 1;    // one added to answer to show fail.
                    }

                    */

                    string lowercaseInput = userInput.ToLower();            // Convert string to lowercase


                    // Check for bad words & SQL injection

                    foreach (string word in badWords)
                    {
                        // Cycle through bad word list
                        if (lowercaseInput.Contains(word))
                        {
                            answer = answer + 1;    // one added to answer to show fail.
                            Debug.WriteLine("Validation failed at - alphabetValidation - bad word was: " + word);
                            _logger.LogWarning("Validation failed at - alphabetValidation - bad word was: " + word);
                        }
                    }


                    return answer;
                }

                Debug.WriteLine("NULL or BLANK userInput in Validation.alphabetValidation");
                _logger.LogWarning("NULL or BLANK userInput in Validation.alphabetValidation");
                return 1; // Validation failed. Blank or null.

            }
            catch (Exception ex)
            {

                Debug.WriteLine("Error in Validation.alphabetValidation - " + ex);
                _logger.LogError("Error in Validation.alphabetValidation - " + ex);
                return 1;   // Validation failed.
            }
        }




        // Validates fields that should only contain numbers
        // Convert to string first so we can check its length
        // int can be -2,147,483,648 to 2,147,483,647 but our program will not use anywhere near this range. We also don't want user sending extremely long numbers.
        // Check int isn't more than 10 digits.
        public int numberValidation(string userInput)
        {
            try
            {
                int answer = 0;

                // Check for null or blank input.
                if (!String.IsNullOrEmpty(userInput))
                {

                    // Check length and for blanks
                    if (userInput.Length > 10)
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - numberValidation - Input was greater than 10 characters");
                        _logger.LogWarning("Validation failed at - numberValidation - Input was greater than 10 characters");
                    }


                    // Check for integers only

                    // Regex
                    // ^ = start atbeginning of the string
                    // [0-9] = match any numbers 0-9
                    // + = match more than once occurence of this
                    // $ = end of the string
                    if (Regex.IsMatch(userInput, @"^[0-9]+$"))
                    {

                        //Console.WriteLine(String.Format("Regex Validation Passed...." + userInput), "Info");
                    }
                    else
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - numberValidation - Regex check doesn't think input was a number");
                        _logger.LogWarning("Validation failed at - numberValidation - Regex check doesn't think input was a number");
                    }

                    string lowercaseInput = userInput.ToLower();            // Convert string to lowercase

                    // Check for bad words & SQL injection

                    foreach (string word in badWords)
                    {                                                       // Cycle through bad world list
                        if (lowercaseInput.Contains(word))
                        {
                            answer = answer + 1;                               // one added to answer to show fail.
                            Debug.WriteLine("Validation failed at - numberValidation - bad word was: " + word);
                            _logger.LogWarning("Validation failed at - numberValidation - bad word was: " + word);
                        }
                    }


                    return answer;
                }

                Debug.WriteLine("NULL or BLANK userInput in Validation.numberValidation");
                _logger.LogWarning("NULL or BLANK userInput in Validation.numberValidation");
                return 1; // Validation failed. Blank or null.

            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error in Validation.numberValidation - " + ex);
                _logger.LogError("Error in Validation.numberValidation - " + ex);
                return 1;   // Validation failed.
            }
        }





        // Validates email addresses.
        // Accepts subdomains you@subdomain.you.com
        // Doesn't accept ..com, two @s, you.com7 
        public int emailValidation(string userInput)
        {
            try
            {
                int answer = 0;

                // Check for null or blank input.
                if (!String.IsNullOrEmpty(userInput))
                {

                    //Check length

                    if (userInput.Length > 50)
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - emailValidation - Input was greater than 50 characters");
                        _logger.LogWarning("Validation failed at - emailValidation - Input was greater than 50 characters");
                    }


                    // Check for correct email address

                    // Regex
                    // Matches email addresses with subdomains, @ symbol, avoids double dots etc
                    // Found online: https://www.rhyous.com/2010/06/15/csharp-email-regular-expression/
                    if (Regex.IsMatch(userInput, @"^[\w!#$%&'*+\-/=?\^_`{|}~]+(\.[\w!#$%&'*+\-/=?\^_`{|}~]+)*@((([\-\w]+\.)+[a-zA-Z]{2,4})|(([0-9]{1,3}\.){3}[0-9]{1,3}))\z"))
                    {

                        //Debug.WriteLine(String.Format("Email Validation Passed...." + userInput), "Info");
                    }
                    else
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - emailValidation - Regex check doesn't think email address is valid");
                        _logger.LogWarning("Validation failed at - emailValidation - Regex check doesn't think email address is valid");
                    }


                    string lowercaseInput = userInput.ToLower();            // Convert string to lowercase


                    // Check for bad words & SQL injection

                    foreach (string word in badWords)
                    {                                                       // Cycle through bad world list
                        if (lowercaseInput.Contains(word))
                        {
                            answer = answer + 1;                               // one added to answer to show fail.
                            Debug.WriteLine("Validation failed at - emailValidation - bad word was: " + word);
                            _logger.LogWarning("Validation failed at - emailValidation - bad word was: " + word);
                        }
                    }


                    return answer;
                }

                Debug.WriteLine("NULL or BLANK userInput in Validation.emailValidation");
                _logger.LogWarning("NULL or BLANK userInput in Validation.emailValidation");
                return 1; // Validation failed. Blank or null.

            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error in Validation.emailValidation - " + ex);
                _logger.LogError("Error in Validation.emailValidation - " + ex);
                return 1;   // Validation failed.
            }
        }



        // Validate DateTime
        // Check it's in Utc format
        public int dateTimeUtcValidation(DateTime date)
        {
            try
            {
                int answer = 0;

                // Check format of date time is in Utc
                if (date.Kind != DateTimeKind.Utc)
                {
                    // Not in Utc format
                    answer = answer + 1;
                    Debug.WriteLine("Validation failed at - dateTimeUtcValidation - Input was not in UTC format");
                    _logger.LogWarning("Validation failed at - dateTimeUtcValidation - Input was not in UTC format");

                    return answer;
                }

                string lowercaseInput = date.ToString().ToLower();            // Convert to lowercase string

                // Check for bad words & SQL injection
                foreach (string word in badWords)
                {                                                       // Cycle through bad world list
                    if (lowercaseInput.Contains(word))
                    {
                        answer = answer + 1;                               // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - dateTimeUtcValidation - bad word was: " + word);
                        _logger.LogWarning("Validation failed at - dateTimeUtcValidation - bad word was: " + word);
                    }
                }

                return answer;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error in Validation.dateTimeUtcValidation - " + ex);
                _logger.LogError("Error in Validation.dateTimeUtcValidation - " + ex);
                return 1;   // Validation failed.
            }
        }


        // Validates JWT Tokens
        public int jwtTokenValidation(string userInput)
        {
            try
            {
                int answer = 0;

                // Check for null or blank input.
                if (!String.IsNullOrEmpty(userInput))
                {

                    // Check length and for blanks
                    // JWT tokens can be varying lengths. My Average is 300 characters.
                    if (userInput.Length > 2000)
                    {
                        answer = answer + 1;    // one added to answer to show fail.
                        Debug.WriteLine("Validation failed at - jwtTokenValidation - input was greater than 2000");
                        _logger.LogWarning("Validation failed at - jwtTokenValidation - input was greater than 2000");
                    }

                    string lowercaseInput = userInput.ToLower();            // Convert string to lowercase


                    // Check for bad words & SQL injection
                    // JWT Tokens may randomly generate some öf the bad words on our list so use a cut down sql-injection-only list "jwtTokenBadWords"
                    foreach (string word in jwtTokenBadWords)
                    {
                        // Cycle through bad word list
                        if (lowercaseInput.Contains(word))
                        {
                            answer = answer + 1;    // one added to answer to show fail.
                            Debug.WriteLine("Validation failed at - jwtTokenValidation - bad word was: " + word);
                            _logger.LogWarning("Validation failed at - jwtTokenValidation - bad word was: " + word);
                        }
                    }


                    return answer;

                }

                Debug.WriteLine("NULL or BLANK userInput in Validation.jwtTokenValidation");
                _logger.LogWarning("NULL or BLANK userInput in Validation.jwtTokenValidation");
                return 1; // Validation failed. Blank or null.

            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error in Validation.jwtTokenlValidation - " + ex);
                _logger.LogError("Error in Validation.jwtTokenlValidation - " + ex);
                return 1;   // Validation failed.
            }
        }



    }
}
