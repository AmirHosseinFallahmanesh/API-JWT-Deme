using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;

namespace WebApi.Entities
{
    public class User
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }

      
        public string Password { get; set; }
        public string Role { get;  set; }
    }

    public class DemoContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public DemoContext(DbContextOptions<DemoContext> dbContextOptions):base(dbContextOptions)
        {

        }
    }
}