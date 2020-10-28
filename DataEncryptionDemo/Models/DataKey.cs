namespace DataEncryptionDemo.Models
{
    public class DataKey
    {
        public int Id { get; set; }
        public byte[] Key { get; set; }
        public string KeyAsString { get; set; }
    }
}