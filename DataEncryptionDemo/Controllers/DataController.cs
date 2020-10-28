using System.Threading.Tasks;
using DataEncryptionDemo.Data;
using DataEncryptionDemo.Helpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DataEncryptionDemo.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class DataController : ControllerBase
    {
        private readonly ApplicationDbContext _dbContext;

        public DataController(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var key = await _dbContext.DataKeys.FirstOrDefaultAsync();
            var patient = await _dbContext.Patients.FirstOrDefaultAsync();

            var decryptedKey = key.KeyAsString.Decrypt();

            return Ok(new
            {
                KeyFromBytes = key.Key.DecryptFromByteArray(),
                KeyFromString = key.KeyAsString.Decrypt(),
                patient.RawNric,
                EncryptedNric = patient.Nric,
                DecryptedNric = patient.Nric.AesDecrypt(decryptedKey)
            });
        }
    }
}