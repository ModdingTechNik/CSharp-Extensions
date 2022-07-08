using CSharp.Extensions.Security.Cryptography;

namespace CSharp.Extensions.UnitMSTests.Security.Cryptography;

[TestClass]
public class CryptographicHashStringTest
{
    [TestMethod]
    public void EqualsTyped()
    {
        CryptographicHashString hashString1 = "test1";
        CryptographicHashString hashString2 = "test1";
        CryptographicHashString clone = (CryptographicHashString)hashString1.Clone();
        
        Assert.IsTrue(hashString1.Equals(clone));
        Assert.IsTrue(clone.Equals(hashString1));
        
        Assert.IsFalse(hashString1.Equals(hashString2));
        Assert.IsFalse(clone.Equals(hashString2));
        
        Assert.IsFalse(hashString2.Equals(hashString1));
        Assert.IsFalse(hashString2.Equals(clone));
    }
    
    [TestMethod]
    public void EqualsObject()
    {
        CryptographicHashString hashString1 = "test1";
        object hashString2 = new CryptographicHashString("test1");
        object clone = hashString1.Clone();
        
        Assert.IsTrue(hashString1.Equals(clone));
        Assert.IsTrue(clone.Equals(hashString1));
        
        Assert.IsFalse(hashString1.Equals(hashString2));
        Assert.IsFalse(clone.Equals(hashString2));
        
        Assert.IsFalse(hashString2.Equals(hashString1));
        Assert.IsFalse(hashString2.Equals(clone));
    }
    
    [TestMethod]
    public void CompareToTyped()
    {
        CryptographicHashString hashString1 = "test1";
        CryptographicHashString hashString2 = "test1";
        CryptographicHashString clone = (CryptographicHashString)hashString1.Clone();

        Assert.AreEqual(0, hashString1.CompareTo(clone));
        Assert.AreEqual(0, clone.CompareTo(hashString1));

        Assert.AreEqual(1, hashString1.CompareTo(hashString2));
        Assert.AreEqual(1,  clone.CompareTo(hashString2));

        Assert.AreEqual(1, hashString2.CompareTo(hashString1));
        Assert.AreEqual(1, hashString2.CompareTo(clone));
    }
    
    [TestMethod]
    public void CompareToObject()
    {
        CryptographicHashString hashString1 = "test1";
        CryptographicHashString hashString2 = new CryptographicHashString("test1");
        object clone = hashString1.Clone();
        
        Assert.AreEqual(0, hashString1.CompareTo(clone));

        Assert.AreEqual(1, hashString1.CompareTo(hashString2));

        Assert.AreEqual(1, hashString2.CompareTo(hashString1));
        Assert.AreEqual(1, hashString2.CompareTo(clone));
    }
    
    [TestMethod]
    public void OperatorEquals()
    {
        CryptographicHashString hashString1 = "test1";
        CryptographicHashString hashString2 = new CryptographicHashString("test1");
        CryptographicHashString clone = (CryptographicHashString)hashString1.Clone();
        
        Assert.IsTrue(hashString1 == clone);
        Assert.IsTrue(clone == hashString1);
        
        Assert.IsFalse(hashString1 == hashString2);
        Assert.IsFalse(clone == hashString2);
        
        Assert.IsFalse(hashString2 == hashString1);
        Assert.IsFalse(hashString2 == clone);
    }

    [TestMethod]
    public void OperatorCompare()
    {
        CryptographicHashString hashString = "test1";
        string str1 = hashString.ToString();
        string str2 = new CryptographicHashString("test2");
        
        Assert.IsTrue(str1 & hashString);
        Assert.IsTrue(hashString & str1);
        
        Assert.IsFalse(str2 & hashString);
        Assert.IsFalse(hashString & str2);
    }
    

    [TestMethod]
    public void Parse()
    {
        CryptographicHashString hashString = "test1";
        string str = hashString.ToString();

        CryptographicHashString result = CryptographicHashString.Parse(str);

        Assert.IsNotNull(result);
        Assert.IsTrue(hashString.Equals(result));

        Assert.ThrowsException<CryptographicHashStringParseException>(() => CryptographicHashString.Parse("test"));
    }
    
    [TestMethod]
    public void TryParse()
    {
        CryptographicHashString hashString = "test1";
        string str = hashString.ToString();

        bool tryParse1 = CryptographicHashString.TryParse(str, out CryptographicHashString result1);
        
        Assert.IsTrue(tryParse1); 
        Assert.IsNotNull(result1);
        Assert.IsTrue(hashString.Equals(result1));
        
        bool tryParse2 = CryptographicHashString.TryParse("test", out CryptographicHashString result2);
        
        Assert.IsFalse(tryParse2);
        Assert.IsNotNull(result2);
        Assert.IsTrue(result2.Equals(CryptographicHashString.Empty));
    }
    
    [TestMethod]
    public void Compare()
    {
        CryptographicHashString hashString = "test1";
        string str1 = hashString.ToString();
        string str2 = new CryptographicHashString("test2");
        
        Assert.IsTrue(CryptographicHashString.Compare(str1, hashString));
        
        Assert.IsFalse(CryptographicHashString.Compare(str2, hashString));
        Assert.IsFalse(CryptographicHashString.Compare("test", hashString));
    }
}