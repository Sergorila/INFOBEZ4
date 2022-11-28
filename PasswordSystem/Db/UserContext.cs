using Microsoft.EntityFrameworkCore;
using SergeyREST.Models;

namespace SergeyREST.Db
{
    public class UserContext : DbContext
    {
        public UserContext() : base()
        {
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured) 
            {
                optionsBuilder.UseSqlServer(@"Server=DESKTOP-RBPOQG7\SQLEXPRESS; Database=PasswordSystem; Trusted_Connection=True;");
            }
        }

        public DbSet<User> Users { get; set; }
    }
}
