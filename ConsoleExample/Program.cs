using System;
using CSharp.Extensions.Security.Cryptography;

namespace ConsoleExample;

internal static class Program
{
    private static void Main()
    {
        // Example
        
        string str = Console.ReadLine() ?? ""; // string entered by the user

        CryptographicHashString hashString = str; // default hash

        string dbStr = hashString; // default hash e.g. from a database
        
        Console.WriteLine(dbStr & hashString); // comparison output
        Console.WriteLine(hashString & dbStr); // comparison output
        
        // analogue of dbStr & hashString is CryptographicHashString.Compare(dbStr, hashString);
    }
}