using System;
using System.Security.Cryptography;
using System.Text;

namespace CSharp.Extensions.Security.Cryptography;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public sealed class CryptographicHashString
{
    private const int DefaultHashSize = 32;
    private const int DefaultSaltSize = 32;
    private const int DefaultIterationsAmount = 2920;
    private const char Separator = '|';
    private static readonly HashAlgorithmName DefaultHashAlgorithmName = HashAlgorithmName.SHA384;
    
    private readonly string _base64Hash;
    private readonly string _base64Salt;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly int _hashSize;
    private readonly int _iterations;

    public CryptographicHashString(string origin,
        int saltSize = DefaultSaltSize, 
        int hashSize = DefaultHashSize, 
        int iterations = DefaultIterationsAmount) :
        this(origin, DefaultHashAlgorithmName, saltSize, hashSize, iterations) 
    { }

    public CryptographicHashString(string origin, HashAlgorithmName hashAlgorithm,
        int saltSize = DefaultSaltSize, 
        int hashSize = DefaultHashSize, 
        int iterations = DefaultIterationsAmount)
    {
        (string hash, string salt) = GetHash(origin, saltSize, iterations, hashAlgorithm, hashSize);
        
        _base64Hash = hash;
        _base64Salt = salt;
        _hashAlgorithm = hashAlgorithm;
        _hashSize = hashSize;
        _iterations = iterations;
    }

    public bool Equals(CryptographicHashString other)
    {
        return _base64Hash == other._base64Hash && _base64Salt == other._base64Salt;
    }

    public override bool Equals(object? obj)
    {
        return ReferenceEquals(this, obj) || obj is CryptographicHashString other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_base64Hash, _base64Salt);
    }

    public override string ToString()
    {
        StringBuilder builder = new StringBuilder(_base64Hash.Length + _base64Salt.Length + 1);
        builder.Append(_base64Hash);
        builder.Append(Separator);
        builder.Append(_base64Salt);
        return builder.ToString();
    }

    public static bool operator ==(CryptographicHashString? left, CryptographicHashString? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CryptographicHashString? left, CryptographicHashString? right)
    {
        return !Equals(left, right);
    }

    public static bool operator &(string left, CryptographicHashString right)
    {
        return Compare(left, right);
    }
    
    public static bool operator &(CryptographicHashString left, string right)
    {
        return Compare(right, left);
    }

    public static bool Compare(string left, CryptographicHashString right)
    {
        byte[] salt = Convert.FromBase64String(right._base64Salt);
        string hash = GetHash(left, salt, right._iterations, right._hashAlgorithm, right._hashSize);
        return hash == right._base64Hash;
    }

    private static (string, string) GetHash(string origin, int saltSize, int iterations, HashAlgorithmName hashAlgorithm, int cb)
    {
        Rfc2898DeriveBytes rfc = new(origin, saltSize, iterations, hashAlgorithm);
        
        string base64Salt = Convert.ToBase64String(rfc.Salt);
        string base64Hash = Convert.ToBase64String(rfc.GetBytes(cb));
        
        rfc.Reset();

        return (base64Hash, base64Salt);
    }
    
    private static string GetHash(string origin, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm, int cb)
    {
        Rfc2898DeriveBytes rfc = new(origin, salt, iterations, hashAlgorithm);
        
        string base64Hash = Convert.ToBase64String(rfc.GetBytes(cb));
        
        rfc.Reset();

        return base64Hash;
    }
}