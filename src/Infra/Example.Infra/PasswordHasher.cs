using System.Security.Authentication;
using System.Security.Cryptography;
using Example.Infra.Interfaces;

namespace Example.Infra;

public class PasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int Iterations = 10000;
    private static readonly HashAlgorithmName HashAlgorithmName = HashAlgorithmName.SHA512;

    public string HashPassword(string password)
    {
        var salt = new byte[SaltSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName);
        byte[] hashedBytes = pbkdf2.GetBytes(KeySize);
        byte[] hashBytes = new byte[SaltSize + KeySize];
        Array.Copy(salt, 0, hashBytes, 0, SaltSize);
        Array.Copy(hashedBytes, 0, hashBytes, SaltSize, KeySize);

        return Convert.ToBase64String(hashBytes);
    }

    public bool VerifyPassword(string password, string passwordHash)
    {
        byte[] hashBytes = Convert.FromBase64String(passwordHash);
        byte[] salt = new byte[SaltSize];
        Array.Copy(hashBytes, 0, salt, 0, SaltSize);
        
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName);
        byte[] hashedBytes = pbkdf2.GetBytes(KeySize);
        for (int i = 0; i < KeySize; i++)
        {
            if (hashBytes[i + SaltSize] != hashedBytes[i])
            {
                throw new AuthenticationException("Invalid password");
            }
        }

        return true;
    }
}