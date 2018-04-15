using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.DiffieHellman;
using System.Collections.Generic;

namespace SecurityPackageTest
{
    
    [TestClass]
    public class DiffieHellmanTest
    {
        [TestMethod]
        public void DeffieHelmanTest1()
        {
            DiffieHellman algorithm = new DiffieHellman();
            List<int> key = algorithm.GetKeys(19, 2, 6, 13);
            Assert.AreEqual(key[0], 7);
            Assert.AreEqual(key[1], 7);
        }

        [TestMethod]
        public void DeffieHelmanTest2()
        {
            DiffieHellman algorithm = new DiffieHellman();
            List<int> key = algorithm.GetKeys(353, 2, 97, 233);
            Assert.AreEqual(key[0], 81);
            Assert.AreEqual(key[1], 81);
        }

        [TestMethod]
        public void DeffieHelmanTest3()
        {
            DiffieHellman algorithm = new DiffieHellman();
            List<int> key = algorithm.GetKeys(353, 3, 97, 233);
            Assert.AreEqual(key[0], 160);
            Assert.AreEqual(key[1], 160);
        }

        [TestMethod]
        public void DeffieHelmanNewTest()
        {
            DiffieHellman algorithm = new DiffieHellman();
            List<int> key = algorithm.GetKeys(541, 10, 50, 100);
            Assert.AreEqual(key[0], 449);
            Assert.AreEqual(key[1], 449);
        }
    }
}
