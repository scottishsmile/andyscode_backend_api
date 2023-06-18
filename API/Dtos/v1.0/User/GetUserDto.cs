namespace API.Dtos.v1_0.User
{
    public class GetUserDto
    {
        // The data we want to send back to the admin, left out password and unneeded Identity stuff.

        // In .Net 6 if the field is non-nulable. No "?". then it is a REQUIRED Field!
        // https://stackoverflow.com/questions/72060349/form-field-is-required-even-if-not-defined-so
        public string? Id { get; set; }
        public string? Email { get; set; }
        public bool? EmailVerified { get; set; }
        public string? UserName { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
        public IList<string>? Roles { get; set; }

        public string? AddressNumber { get; set; }                  // Could be 12A or Flat 2
        public string? AddressLine1 { get; set; }
        public string? AddressLine2 { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? PostCode { get; set; }

        public string? Language { get; set; }
        public string? Timezone { get; set; }
        public bool? AccountLocked { get; set; }
        public DateTime? LastLogin { get; set; }
        public DateTime? RegistrationDate { get; set; }
    }
}
