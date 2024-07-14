namespace Backend.Models
{
    public class EmailModel
    {
        public string Content { get; set; }
        public string Subject { get; set; }
        public string To { get; set; }
        public EmailModel(string to,string subject, string content)
        {
            To = to;
            Subject = subject;
            Content = content;
        }
    }
}
