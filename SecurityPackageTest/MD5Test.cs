using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.MD5;

namespace SecurityPackageTest
{
    [TestClass]
    public class MD5Test
    {
        [TestMethod]
        public void MD5Test1()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("abcdefgh");
            Assert.IsTrue(hash.Equals("E8DC4081B13434B45189A720B77B6818", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test2()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            Assert.IsTrue(hash.Equals("80DAD3AAD8584778352C68AB06250327", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test3()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("");
            Assert.IsTrue(hash.Equals("D41D8CD98F00B204E9800998ECF8427E", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test4()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("The quick brown fox jumps over the lazy dog");
            Assert.IsTrue(hash.Equals("9E107D9D372BB6826BD81D3542A419D6", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test5()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("The quick brown fox jumps over the lazy dog.");
            Assert.IsTrue(hash.Equals("E4D909C290D0FB1CA068FFADDF22CBD0", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test6()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("qwertyuiopasdfghjklzxcvbnm");
            Assert.IsTrue(hash.Equals("E5DAAA90C369ADFD156862D6DF632DED", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5Test7()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("kndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbffbekjfbwekjbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfebfkjebgkjwebgkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbfkndflkandfanqflqnwfaaknsdfjsbdfhs jasdb dasjkfbajk9u4238hrfkjdbffbweufbweugbu");
            Assert.IsTrue(hash.Equals("91516cddeec3d6b4672ece1ab19f450a", StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MD5NewTest()
        {
            MD5 algorithm = new MD5();
            string hash = algorithm.GetHash("This is a security test");
            Assert.IsTrue(hash.Equals("ca84feb859d390498ab49b2aad8e4fb4", StringComparison.InvariantCultureIgnoreCase));
        }
    }
}
