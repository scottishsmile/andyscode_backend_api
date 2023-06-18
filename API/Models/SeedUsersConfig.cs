namespace API.Models
{
    public class SeedUsersConfig
    {
        public string? UserName { get; set; }
        public string? Role { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
        public string? AddressNumber { get; set; }                  // Could be 12A or Flat 2
        public string? AddressLine1 { get; set; }
        public string? AddressLine2 { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? PostCode { get; set; }
        public string? Language { get; set; }
        public string? Timezone { get; set; }
        public bool Newsletter { get; set; } = false;


        public DateTime? LastLogin { get; set; } = DateTime.UtcNow;
        public DateTime? RegistrationDate { get; set; } = DateTime.UtcNow;
        public bool EnableMFA { get; set; } = false;
    }
}
