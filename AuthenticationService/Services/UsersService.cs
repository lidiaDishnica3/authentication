using AuthenticationService.Data;
//using AuthenticationService.Entities;
using AuthenticationService.Interfaces;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationService.Services
{
    public class UsersService : IUsersService
    {
        private readonly AuthenticationAppContext _context;

        public UsersService(AuthenticationAppContext context)
        {
            _context = context;
        }
        public async Task AddUser(ApplicationUser user)
        {
            try
            {
                await _context.AddAsync(user);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task DeleteUser(ApplicationUser user)
        {
            try
            {
                _context.Remove(user);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<ApplicationUser> GetUserById(string id)
        {
            try
            {
                return await _context.Set<ApplicationUser>().FindAsync(id);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<ApplicationUser> GetUserByStringId(string id)
        {
            try
            {
                return await _context.Set<ApplicationUser>().FindAsync(id);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task<IEnumerable<ApplicationUser>> GetUsers()
        {
            try
            {
                return await _context.Set<ApplicationUser>().ToListAsync();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public async Task SaveChanges()
        {
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public void UpdateUser(ApplicationUser user)
        {
            try
            {
                _context.Update(user);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
