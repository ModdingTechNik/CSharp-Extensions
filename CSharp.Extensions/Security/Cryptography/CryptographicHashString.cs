using System;
using System.Security.Cryptography;
using System.Text;

namespace CSharp.Extensions.Security.Cryptography;

public sealed class CryptographicHashString
{
    private const int DefaultHashSize = 32;
    private const int DefaultSaltSize = 32;
    private const int DefaultIterationsAmount = 2920;
    private const char DefaultSeparator = '|';
    private static readonly HashAlgorithmName DefaultHashAlgorithmName = HashAlgorithmName.SHA384;
    
    private readonly string _base64Hash;
    private readonly string _base64Salt;
    private readonly char _separator;

    public CryptographicHashString(string origin, 
        char separator = DefaultSeparator, 
        int saltSize = DefaultSaltSize, 
        int hashSize = DefaultHashSize, 
        int iterations = DefaultIterationsAmount) :
        this(origin, DefaultHashAlgorithmName, separator, saltSize, hashSize, iterations) 
    { }

    public CryptographicHashString(string origin, HashAlgorithmName hashAlgorithm, 
        char separator = DefaultSeparator, 
        int saltSize = DefaultSaltSize, 
        int hashSize = DefaultHashSize, 
        int iterations = DefaultIterationsAmount)
    {
        (string hash, string salt) = GetHash(origin, saltSize, iterations, hashAlgorithm, hashSize);
        
        _base64Hash = hash;
        _base64Salt = salt;
        _separator = separator;
    }

    private bool Equals(CryptographicHashString other)
    {
        return _base64Hash == other._base64Hash && _base64Salt == other._base64Salt && _separator == other._separator;
    }

    public override bool Equals(object? obj)
    {
        return ReferenceEquals(this, obj) || obj is CryptographicHashString other && Equals(other);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(_base64Hash, _base64Salt, _separator);
    }

    public static bool operator ==(CryptographicHashString? left, CryptographicHashString? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CryptographicHashString? left, CryptographicHashString? right)
    {
        return !Equals(left, right);
    }

    public override string ToString()
    {
        StringBuilder builder = new StringBuilder(_base64Hash.Length + _base64Salt.Length + 1);
        builder.Append(_base64Hash);
        builder.Append(_separator);
        builder.Append(_base64Salt);
        return builder.ToString();
    }

    private static (string, string) GetHash(string origin, int saltSize, int iterations, HashAlgorithmName hashAlgorithm, int cb)
    {
        Rfc2898DeriveBytes rfc = new(origin, saltSize, iterations, hashAlgorithm);
        
        string base64Salt = Convert.ToBase64String(rfc.Salt);
        string base64Hash = Convert.ToBase64String(rfc.GetBytes(cb));
        
        rfc.Reset();

        return (base64Hash, base64Salt);
    }
}