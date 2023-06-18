namespace API.Dtos.v2_0.User
{
    public class GetPagedUserDto
    {
        // A list of users.
        public List<GetUserDto> Users { get; set; }

        // This Dto is for use with Tables / GridViews that need paging information
        // For counting how many "Pages" are in the database and what page we are on.
        // 500 Records? Break that into 10 pages of 50 records.
        public int CurrentPageIndex { get; set; }
        public int PageCount { get; set; }

    }
}
