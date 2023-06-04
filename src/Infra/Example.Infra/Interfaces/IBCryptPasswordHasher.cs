namespace Example.Infra.Interfaces;

public interface IBCryptPasswordHasher : IPasswordHasher
{
    public string HashPassword(string password, string salt);
}