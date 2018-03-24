using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.AES;

namespace SecurityPackageTest
{
    [TestClass]
    public class ExtendedEuclidTest
    {
        [TestMethod]
        public void ExtendedEuclidTest1()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(23, 26);
            Assert.AreEqual(res, 17);
        }

        [TestMethod]
        public void ExtendedEuclidTest2()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(22, 26);
            Assert.AreEqual(res, -1);
        }

        [TestMethod]
        public void ExtendedEuclidTest3()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(50, 71);
            Assert.AreEqual(res, 27);
        }

        [TestMethod]
        public void ExtendedEuclidTest4()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(43, 64);
            Assert.AreEqual(res, 3);
        }

        [TestMethod]
        public void ExtendedEuclidTest5()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(1111, 22222);
            Assert.AreEqual(res, 11101);
        }

        [TestMethod]
        public void ExtendedEuclidTest6()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(123456789, 1236);
            Assert.AreEqual(res, -1);
        }

        [TestMethod]
        public void ExtendedEuclidTest7()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(123456789, 12365);
            Assert.AreEqual(res, 3729);
        }

        [TestMethod]
        public void ExtendedEuclidNewTest()
        {
            ExtendedEuclid algorithm = new ExtendedEuclid();
            int res = algorithm.GetMultiplicativeInverse(13245687, 135469);
            Assert.AreEqual(res, 38164);
        }
    }
}
