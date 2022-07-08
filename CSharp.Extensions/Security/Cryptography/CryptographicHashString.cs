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

    public static readonly CryptographicHashString Empty = new("", "");
    
    private static readonly HashAlgorithmName DefaultHashAlgorithmName = HashAlgorithmName.SHA384;

    private readonly string _base64Hash;
    private readonly string _base64Salt;

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
    }

    private CryptographicHashString(string base64Hash, string base64Salt)
    {
        _base64Hash = base64Hash;
        _base64Salt = base64Salt;
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

    public static implicit operator CryptographicHashString(string origin)
    {
        return new CryptographicHashString(origin);
    }

    public static implicit operator string(CryptographicHashString hashString)
    {
        return hashString.ToString();
    }

    public static bool TryParse(string str, out CryptographicHashString chs)
    {
        string[] base64Values = str.Split(Separator);
        
        if (base64Values.Length < 2 || string.IsNullOrEmpty(base64Values[0]) || string.IsNullOrEmpty(base64Values[1]))
        {
            chs = Empty;
            return false;
        }

        chs = new CryptographicHashString(base64Values[0], base64Values[1]);
        return true;
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