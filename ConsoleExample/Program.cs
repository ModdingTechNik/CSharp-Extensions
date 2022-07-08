using System;
using CSharp.Extensions.Security.Cryptography;

namespace ConsoleExample;

internal static class Program
{
    private static void Main()
    {
        string str = Console.ReadLine() ?? "";
        
        CryptographicHashString hashString = new(str);

        string dbStr = hashString.ToString();
        
        if (CryptographicHashString.TryParse(dbStr, out CryptographicHashString dbHashString))
        {
            Console.WriteLine(dbHashString == hashString);
        }
    }
}