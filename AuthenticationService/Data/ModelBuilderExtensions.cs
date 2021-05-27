//using AuthenticationService.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationService.Data
{
    public static class ModelBuilderExtensions
    {
        public static void Seed(this ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IdentityRole>().HasData(
               new IdentityRole
               {
                   Id = "1",
                   Name = "Admin",
                   ConcurrencyStamp = "",
                   NormalizedName = "Admin"
               },
               new IdentityRole
               {
                   Id = "2",
                   Name = "Client",
                   ConcurrencyStamp = "",
                   NormalizedName = "Client"
               }

           );
            var hasher = new PasswordHasher<ApplicationUser>();
            modelBuilder.Entity<ApplicationUser>().HasData(
                new ApplicationUser
                {
                    Id = "a4c95d33-b702-499c-b436-621e786e7518",
                    Email = "atisadmin@atis.al",
                    FirstName = "Atis",
                    LastName = "Admin",
                    PasswordHash = hasher.HashPassword(null, "Admin123*"),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = "atisadmin@atis.al",
                    NormalizedUserName = "atisadmin@atis.al".ToUpper(),
                    NormalizedEmail = "atisadmin@atis.al".ToUpper(),
                }
            );
        }
    }

}
