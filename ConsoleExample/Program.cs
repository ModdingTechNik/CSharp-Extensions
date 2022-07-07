using System;
using System.Security.Cryptography;
using CSharp.Extensions.Security.Cryptography;

namespace ConsoleExample;

internal static class Program
{
    private static void Main()
    {
        string str = Console.ReadLine() ?? "";
        CryptographicHashString hashString = new(str, '|', 32, 32, 2048, HashAlgorithmName.SHA384);
        Console.WriteLine(hashString);
    }
}