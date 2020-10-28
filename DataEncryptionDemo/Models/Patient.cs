namespace DataEncryptionDemo.Models
{
    public class Patient
    {
        public int Id { get; set; }

        public string RawNric { get; set; }
        public string Nric { get; set; }
    }
}