using JWTIdentityClassLib.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace JWTIdentityClassLib.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        private readonly IConfiguration Configuration;

        public ApplicationDbContext() : base() { }
        
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options,
            IConfiguration configuration) : base(options)
        {
            this.Configuration = configuration;
        }

        //public static string GetConnectionString()
        //{
        //    var builder = new ConfigurationBuilder()
        //     .SetBasePath(Path.Combine(Directory.GetCurrentDirectory()))
        //     .AddJsonFile("appsettings.json");

        //    //var config = builder.Build();
        //    IConfiguration Configuration = builder.Build();
        //    //return Configuration["ConnectionStrings:DefaultConnection"];
        //    return Configuration.GetConnectionString("IdentityDatabase");
        //}

        //protected override void OnConfiguring(DbContextOptionsBuilder options)
        //{
        //    // connect to sqlserver database
        //    //options.UseSqlServer(Configuration.GetConnectionString("IdentityDatabase"));
        //    options.UseSqlServer("Server=localhost,1433;Database=IdentityDB;User=sa;Password=Pass#Word1");
        //}

        // DBSET....is here...
        public DbSet<RefreshToken> RefreshTokens { get; set; }

    }
}
