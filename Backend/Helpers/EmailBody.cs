namespace Backend.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email, string emailToken)
        {
            return $@"<html>    
                  <head>
                        
                </head>
                <body>
                    <a href=""http://localhost:4200/reset?email={email}&code={emailToken}"" >Reset Password</a>
                </body>
                    </html>
            ";
        }
    }
}
