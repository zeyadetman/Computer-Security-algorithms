using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.AES;

namespace SecurityPackageTest
{
    [TestClass]
    public class AESTest
    {
        string mainPlain = "0x3243F6A8885A308D313198A2e0370734";
        string mainCipher = "0x3925841D02DC09FBDC118597196A0B32";
        string mainKey = "0x2B7E151628AED2A6ABF7158809CF4F3C";

        string mainPlain2 = "0x00000000000000000000000000000001";
        string mainCipher2 = "0x58e2fccefa7e3061367f1d57a4e7455a";
        string mainKey2 = "0x00000000000000000000000000000000";

        string mainPlain3 = "0x00112233445566778899aabbccddeeff";
        string mainCipher3 = "0x69c4e0d86a7b0430d8cdb78070b4c55a";
        string mainKey3 = "0x000102030405060708090a0b0c0d0e0f";

        string newPlain = "0x54776F204F6E65204E696E652054776F";
        string newCipher = "0x29C3505F571420F6402299B31A02D73A";
        string newKey = "0x5468617473206D79204B756E67204675";

        [TestMethod]
        public void AESTestEnc1()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain, mainKey);
            Assert.IsTrue(cipher.Equals(mainCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec1()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher, mainKey);
            Assert.IsTrue(plain.Equals(mainPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestEnc2()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain2, mainKey2);
            Assert.IsTrue(cipher.Equals(mainCipher2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec2()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher2, mainKey2);
            Assert.IsTrue(plain.Equals(mainPlain2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestEnc3()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(mainPlain3, mainKey3);
            Assert.IsTrue(cipher.Equals(mainCipher3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestDec3()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(mainCipher3, mainKey3);
            Assert.IsTrue(plain.Equals(mainPlain3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestNewEnc()
        {
            AES algorithm = new AES();
            string cipher = algorithm.Encrypt(newPlain, newKey);
            Assert.IsTrue(cipher.Equals(newCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void AESTestNewDec()
        {
            AES algorithm = new AES();
            string plain = algorithm.Decrypt(newCipher, newKey);
            Assert.IsTrue(plain.Equals(newPlain, StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
