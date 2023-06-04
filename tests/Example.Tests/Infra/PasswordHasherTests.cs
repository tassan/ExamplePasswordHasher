using System.Security.Authentication;
using Example.Infra;
using Xunit.Abstractions;

namespace Example.Tests.Infra;

[Trait("Category", "Unit")]
[Trait("Infra", "Security")]
public class PasswordHasherTests
{
    private PasswordHasher PasswordHasher { get; set; }
    private BCryptPasswordHasher BCryptPasswordHasher { get; set; }
    
    private readonly ITestOutputHelper _testOutputHelper;
    
    public PasswordHasherTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
        PasswordHasher = new PasswordHasher();
        BCryptPasswordHasher = new BCryptPasswordHasher();
    }
    
    [Fact]
    [Trait("Security", "HashPassword")]
    public void HashPassword_ShouldReturnHashedPassword()
    {
        var password = "password";
        var hashedPassword = PasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.NotEqual(password, hashedPassword);
    }
    
    [Fact]
    [Trait("Security", "VerifyPassword")]
    public void VerifyPassword_ShouldReturnTrue()
    {
        var password = "password";
        var hashedPassword = PasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.True(PasswordHasher.VerifyPassword(password, hashedPassword));
    }

    [Fact]
    [Trait("Security", "VerifyPassword")]
    public void VerifyPassword_ShouldThrowAuthenticationException()
    {
        var password = "password";
        var hashedPassword = PasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.Throws<AuthenticationException>(() => PasswordHasher.VerifyPassword("wrongpassword", hashedPassword));
    }
    
    [Fact]
    [Trait("Security", "VerifyPassword")]
    public void VerifyPassword_ShouldThrowFormatException()
    {
        var password = "password";
        var hashedPassword = PasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.Throws<FormatException>(() => PasswordHasher.VerifyPassword("wrongpassword", "wrongpassword"));
    }
    
    [Fact]
    [Trait("Security", "BCrypt")]
    [Trait("Security", "HashPassword")]
    public void BCryptPasswordHasher_ShouldReturnHashedPassword()
    {
        var password = "password";
        var hashedPassword = BCryptPasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.NotEqual(password, hashedPassword);
    }
    
    [Fact]
    [Trait("Security", "BCrypt")]
    [Trait("Security", "VerifyPassword")]
    public void BCryptPasswordHasher_ShouldReturnTrue()
    {
        var password = "password";
        var hashedPassword = BCryptPasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.True(BCryptPasswordHasher.VerifyPassword(password, hashedPassword));
    }

    [Fact]
    [Trait("Security", "BCrypt")]
    [Trait("Security", "VerifyPassword")]
    public void BCryptPasswordHasher_ShouldReturnFalse()
    {
        var password = "password";
        var hashedPassword = BCryptPasswordHasher.HashPassword(password);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.False(BCryptPasswordHasher.VerifyPassword("wrongpassword", hashedPassword));
    }
    
    [Fact]
    [Trait("Security", "BCrypt")]
    [Trait("Security", "HashPassword")]
    public void BCryptPasswordHasher_ShouldReturnHashedPasswordWithSalt()
    {
        var salt = BCryptPasswordHasher.GenerateSalt();
            
        var password = "password";
        var hashedPassword = BCryptPasswordHasher.HashPassword(password, salt);
        
        _testOutputHelper.WriteLine($"Password: {password}");
        _testOutputHelper.WriteLine($"Hashed Password: {hashedPassword}");
        
        Assert.NotEqual(password, hashedPassword);
    }
}