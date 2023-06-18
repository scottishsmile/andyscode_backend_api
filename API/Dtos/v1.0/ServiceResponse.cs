namespace API.Dtos.v1_0
{
    public class ServiceResponse<T>
    {
        // Generic Class (typically of type <T>)
        // We will use this generic wrapper object for all responces from the server.
        // This way we can give more detailed error messages rather than just the HTTP response codes.

        /*
            Informational responses (100–199)
            Successful responses (200–299)
            Redirects (300–399)
            Client errors (400–499)
            Server errors (500–599)
        */

            public T? Data { get; set; }
            public bool Success { get; set; } = true;
            public string Message { get; set; } = null;
    }
}
