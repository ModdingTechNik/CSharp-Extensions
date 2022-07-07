using System;
using CSharp.Extensions.Security.Cryptography;

namespace ConsoleExample;

internal static class Program
{
    private static void Main()
    {
        string str = Console.ReadLine() ?? "";
        
        CryptographicHashString hashString = new(str);
        
        Console.WriteLine(hashString);
        Console.WriteLine(str & hashString);
        Console.WriteLine(hashString & str);
    }
}