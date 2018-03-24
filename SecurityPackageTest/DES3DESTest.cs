using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.DES;
using System.Collections.Generic;

namespace SecurityPackageTest
{
    [TestClass]
    public class DES3DESTest
    {
        string mainPlain = "0x0123456789ABCDEF";
        string mainCipher = "0x85E813540F0AB405";
        string mainKey = "0x133457799BBCDFF1";

        string mainPlain2 = "0x596F7572206C6970";
        string mainCipher2 = "0xC0999FDDE378D7ED";
        string mainKey2 = "0x0E329232EA6D0D73";

        string mainPlainTriple = "0x0123456789ABCDEF";
        string mainCipherTriple = "0x85E813540F0AB405";
        List<string> mainKeyTriple =  new List<string>() {"0x133457799BBCDFF1", "0x133457799BBCDFF1" };


        string newPlain = "0x6D6573736167652E";
        string newCipher = "0x7CF45E129445D451";
        string newKey = "0x38627974656B6579";

        [TestMethod]
        public void DESTestEnc1()
        {
            DES algorithm = new DES();
            string cipher = algorithm.Encrypt(mainPlain, mainKey);
            Assert.IsTrue(cipher.Equals(mainCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void DESTestDec1()
        {
            DES algorithm = new DES();
            string plain = algorithm.Decrypt(mainCipher, mainKey);
            Assert.IsTrue(plain.Equals(mainPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void DESTestEnc2()
        {
            DES algorithm = new DES();
            string cipher = algorithm.Encrypt(mainPlain2, mainKey2);
            Assert.IsTrue(cipher.Equals(mainCipher2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void DESTestDec2()
        {
            DES algorithm = new DES();
            string plain = algorithm.Decrypt(mainCipher2, mainKey2);
            Assert.IsTrue(plain.Equals(mainPlain2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TripleDESTestEnc1()
        {
            TripleDES algorithm = new TripleDES();
            string cipher = algorithm.Encrypt(mainPlainTriple, mainKeyTriple);
            Assert.IsTrue(cipher.Equals(mainCipherTriple, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TripleDESTestDec1()
        {
            TripleDES algorithm = new TripleDES();
            string plain = algorithm.Decrypt(mainCipherTriple, mainKeyTriple);
            Assert.IsTrue(plain.Equals(mainPlainTriple, StringComparison.InvariantCultureIgnoreCase));
        }


        [TestMethod]
        public void DESTestNewEnc()
        {
            DES algorithm = new DES();
            string cipher = algorithm.Encrypt(newPlain, newKey);
            Assert.IsTrue(cipher.Equals(newCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void DESTestNewDec()
        {
            DES algorithm = new DES();
            string plain = algorithm.Decrypt(newCipher, newKey);
            Assert.IsTrue(plain.Equals(newPlain, StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
