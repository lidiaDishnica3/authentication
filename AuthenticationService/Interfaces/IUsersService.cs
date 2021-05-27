using AuthenticationService.Data;
//using AuthenticationService.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationService.Interfaces
{
    public interface IUsersService
    {
        Task AddUser(ApplicationUser user);
        Task DeleteUser(ApplicationUser user);
        Task<ApplicationUser> GetUserById(string id);
        Task<ApplicationUser> GetUserByStringId(string id);
        Task<IEnumerable<ApplicationUser>> GetUsers();
        Task SaveChanges();
        void UpdateUser(ApplicationUser user);
    }
}
