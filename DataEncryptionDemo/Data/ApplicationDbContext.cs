using DataEncryptionDemo.Helpers;
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

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var key = "6C14637CC38A4E13A1E41EFF11D883E3";
            var nric = "0001-0001-0001";

            modelBuilder.Entity<DataKey>()
                .HasData(new DataKey()
                {
                    Id = 1,
                    Key = key.EncryptToByteArray(),
                    KeyAsString = key.Encrypt()
                });

            modelBuilder.Entity<Patient>()
                .HasData(new Patient()
                {
                    Id = 1,
                    Nric = nric.AesEncrypt(key),
                    RawNric = nric
                });

            base.OnModelCreating(modelBuilder);
        }

        public DbSet<Patient> Patients { get; set; }
        public DbSet<DataKey> DataKeys { get; set; }
    }
}