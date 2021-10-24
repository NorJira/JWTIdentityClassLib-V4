using System;
namespace JWTIdentityClassLib.Settings
{
    public class JWTSettings
    {
        //"Key": "This is my symmetric jwt key",
        //"Audience": "http://localhost",
        //"Issuer": "http://localhost",
        //"Secret": "All you have to do is call, And I'll be there, yes, I will...You've got a friend",
        //"RefreshTokenTTL": 7,
        //"AcceessTokenTTL": 5
        //
        //public string Key { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }

        public string Secret { get; set; }
        // refresh token time to live (in days), inactive tokens are
        // automatically deleted from the database after this time
        public int RefreshTokenTTL { get; set; }  // in days
        public int AccessTokenTTL { get; set; }   // in minutes
    }
}
