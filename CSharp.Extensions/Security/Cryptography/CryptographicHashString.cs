using System;
using System.Security.Cryptography;
using System.Text;

namespace CSharp.Extensions.Security.Cryptography;

public sealed class CryptographicHashString
{
    private readonly string _base64Hash;
    private readonly string _base64Salt;
    private readonly char _separator;

    public CryptographicHashString(string origin, char separator, int saltSize, int hashSize, int iterations, HashAlgorithmName hashAlgorithm)
    {
        (string hash, string salt) = GetHash(origin, saltSize, iterations, hashAlgorithm, hashSize);
        
        _base64Hash = hash;
        _base64Salt = salt;
        _separator = separator;
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