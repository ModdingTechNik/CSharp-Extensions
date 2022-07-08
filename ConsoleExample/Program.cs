using System;
using CSharp.Extensions.Security.Cryptography;

namespace ConsoleExample;

internal static class Program
{
    private static void Main()
    {
        string str = Console.ReadLine() ?? "";

        CryptographicHashString hashString = str;

        string dbStr = hashString;
        
        Console.WriteLine(dbStr & hashString);
        Console.WriteLine(hashString & dbStr);
    }
}