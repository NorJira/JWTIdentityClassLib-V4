using System;
namespace JWTIdentityClassLib.Settings
{
    public class MailServiceSettings
    {
        //"EmailFrom": "norjira@dotnet-api.com",
        //"SmtpHost": "smtp.ethereal.email",
        //"SmtpPort": 587,
        //"SmtpUser": "carlie.nader@ethereal.email",
        //"SmtpPass": "7VVgpKcXqgrWaf2XKq"
        //
        public string EmailFrom { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUser { get; set; }
        public string SmtpPass { get; set; }
    }
}
