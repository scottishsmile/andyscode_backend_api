using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace API.Validation.v1_0
{
    public interface IValidateV1
    {
        // All methods return 0 if successful.
        // They count the errors so > 0 is a fail.
        public int alphabetValidation(string userInput);       // Valdidate strings. Firstname, Username, Pasword, Email Address, Surname inputs

        public int numberValidation(string userInput);         // Validate numbers. id input

        public int emailValidation(string userInput);          // Validate email addresses

        public int dateTimeUtcValidation(DateTime date);    // Validate DateTime UTC format

        public int jwtTokenValidation(string userInput);        // Validate JWT Tokens. Max token length configured as 1500 characters. Maximum url length is 2048 characters.

    }
}
