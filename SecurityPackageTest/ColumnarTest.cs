using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using SecurityLibrary;

namespace SecurityPackageTest
{
    [TestClass]
    public class ColumnarTest
    {
        string mainPlain1 = "attackpostponeduntiltwoam";
        string mainPlain2 = "attackpostponeduntiltwoamxxx";
        List<int> mainkey = new List<int>() { 4, 3, 1, 2, 5, 6, 7 };

        string mainCipher1 = "ttnaaptmtsuoaodwcoiknlpet".ToUpper();
        string mainCipher2 = "ttnaaptmtsuoaodwcoixknlxpetx".ToUpper();
       
        string mainPlain3 = "computerscience";
        string mainPlain4 = "computersciencex";

        string mainCipher3 = "ctipscoeemrnuce".ToUpper();
        string mainCipher4 = "cusnpremeieotcc".ToUpper();
        string mainCipher5 = "cusnprexmeieotcc".ToUpper();

        List<int> mainkey1 = new List<int>() { 1, 3, 4, 2, 5 };
        List<int> mainkey2 = new List<int>() { 1, 4, 3, 2 };

        string newPlain = "defendtheeastwallofthecastleee";
        string newCipher = "nalceehwttdttfseeleedsoaefeahl";
        
        List<int> newKey = new List<int>() { 3, 2, 6, 4, 1, 5 };

        [TestMethod]
        public void ColumnarTestEnc1()
        {
            Columnar algorithm = new Columnar();
            string cipher = algorithm.Encrypt(mainPlain1, mainkey);
            // Add x's or not
            Assert.IsTrue(cipher.Equals(mainCipher1, StringComparison.InvariantCultureIgnoreCase)
                       || cipher.Equals(mainCipher2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarTestDec1()
        {
            Columnar algorithm = new Columnar();
            string plain1 = algorithm.Decrypt(mainCipher1, mainkey);
            string plain2 = algorithm.Decrypt(mainCipher2, mainkey);

            Assert.IsTrue(plain1.Equals(mainPlain1, StringComparison.InvariantCultureIgnoreCase)
             || plain2.Equals(mainPlain2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarTestAnalysis1()
        {
            Columnar algorithm = new Columnar();
            List<int> key1 = algorithm.Analyse(mainPlain1, mainCipher1);
            List<int> key2 = algorithm.Analyse(mainPlain2, mainCipher2);
            for (int i = 0; i < mainkey.Count; i++)
            {
                Assert.IsTrue(mainkey[i] == key1[i] || mainkey[i] == key2[i]);
            }
        }

        [TestMethod]
        public void ColumnarTestEnc2()
        {
            Columnar algorithm = new Columnar();
            string cipher = algorithm.Encrypt(mainPlain3, mainkey1);
            Assert.IsTrue(cipher.Equals(mainCipher3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarTestEnc3()
        {
            Columnar algorithm = new Columnar();
            string cipher = algorithm.Encrypt(mainPlain3, mainkey2);

            Assert.IsTrue(cipher.Equals(mainCipher4, StringComparison.InvariantCultureIgnoreCase)
                       || cipher.Equals(mainCipher5, StringComparison.InvariantCultureIgnoreCase));
        }
        [TestMethod]
        public void ColumnarTestDec2()
        {
            Columnar algorithm = new Columnar();
            string plain = algorithm.Decrypt(mainCipher3, mainkey1);
            Assert.IsTrue(plain.Equals(mainPlain3, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarTestDec3()
        {
            Columnar algorithm = new Columnar();
            string plain1 = algorithm.Decrypt(mainCipher4, mainkey2);
            string plain2 = algorithm.Decrypt(mainCipher5, mainkey2);


            Assert.IsTrue(plain1.Equals(mainPlain3, StringComparison.InvariantCultureIgnoreCase)
             || plain2.Equals(mainPlain4, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarTestAnalysis2()
        {
            Columnar algorithm = new Columnar();
            List<int> key = algorithm.Analyse(mainPlain3, mainCipher3);

            for (int i = 0; i < mainkey1.Count; i++)
            {
                Assert.IsTrue(mainkey1[i] == key[i]);
            }
        }

        [TestMethod]
        public void ColumnarTestAnalysis3()
        {
            Columnar algorithm = new Columnar();
            List<int> key1 = algorithm.Analyse(mainPlain3, mainCipher4);
            List<int> key2 = algorithm.Analyse(mainPlain4, mainCipher5);

            for (int i = 0; i < mainkey2.Count; i++)
            {
                Assert.IsTrue(mainkey2[i] == key1[i] || mainkey2[i] == key2[i]);
            }
        }

        [TestMethod]
        public void ColumnarNewTestEnc()
        {
            Columnar algorithm = new Columnar();
            string cipher = algorithm.Encrypt(newPlain, newKey);
            Assert.IsTrue(cipher.Equals(newCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarNewTestDec()
        {
            Columnar algorithm = new Columnar();
            string plain1 = algorithm.Decrypt(newCipher, newKey);

            Assert.IsTrue(plain1.Equals(newPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void ColumnarNewTestAnalysis()
        {
            Columnar algorithm = new Columnar();
            List<int> key1 = algorithm.Analyse(newPlain, newCipher);
            for (int i = 0; i < newKey.Count; i++)
            {
                Assert.IsTrue(newKey[i] == key1[i]);
            }
        }
    }
}
