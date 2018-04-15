using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.ElGamal;
using System.Collections.Generic;

namespace SecurityPackageTest
{

    [TestClass]
    public class ElGamalTest
    {
        [TestMethod]
        public void ElGamalEnc1()
        {
            ElGamal algorithm = new ElGamal();
            List<long> cipher = algorithm.Encrypt(7187, 4842, 4464, 19, 19);//191
            Assert.AreEqual(cipher[0], 2781);
            Assert.AreEqual(cipher[1], 437);
        }

        [TestMethod]
        public void ElGamalEnc2()
        {
            ElGamal algorithm = new ElGamal();
            List<long> cipher = algorithm.Encrypt(6323, 4736, 2231, 58, 111);//118
            Assert.AreEqual(cipher[0], 6066);
            Assert.AreEqual(cipher[1], 899);
        }

        [TestMethod]
        public void ElGamalDec1()
        {
            ElGamal algorithm = new ElGamal();
            int plain = algorithm.Decrypt(2781, 437, 191, 7187);
            Assert.AreEqual(plain, 19);
        }

        [TestMethod]
        public void ElGamalDec2()
        {
            ElGamal algorithm = new ElGamal();
            int plain = algorithm.Decrypt(6066, 899, 118, 6323);
            Assert.AreEqual(plain, 111);
        }
    }
}


