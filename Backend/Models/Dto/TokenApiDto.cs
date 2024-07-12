namespace Backend.Models.Dto
{
    public class TokenApiDto
    {
        public string accessToken { get; set; } = string.Empty;
        public string refreshToken { get; set; } = string.Empty;

    }
}
