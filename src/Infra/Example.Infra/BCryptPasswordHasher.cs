using System.Security.Cryptography;
using Example.Infra.Interfaces;

namespace Example.Infra;

public class BCryptPasswordHasher : IBCryptPasswordHasher
{
    public string HashPassword(string password)
    {
        return BC.HashPassword(password);
    }

    public bool VerifyPassword(string password, string passwordHash)
    {
        return BC.Verify(password, passwordHash);
    }

    public string HashPassword(string password, string salt)
    {
        return BC.HashPassword(password, salt);
    }

    public string GenerateSalt() => BC.GenerateSalt();
}