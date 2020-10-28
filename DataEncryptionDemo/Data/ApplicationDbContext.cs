using DataEncryptionDemo.Models;
using Microsoft.EntityFrameworkCore;

namespace DataEncryptionDemo.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Patient> Patients { get; set; }
        public DbSet<DataKey> DataKeys { get; set; }
    }
}