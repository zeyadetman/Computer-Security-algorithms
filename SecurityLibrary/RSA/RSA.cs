using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public DiffieHellman.DiffieHellman obj = new DiffieHellman.DiffieHellman();
        public AES.ExtendedEuclid ex = new AES.ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int me = obj.pow(M, e, n)%n;
            return me;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n2 = p * q;
            int n = (p-1) * (q-1);
            e = ex.GetMultiplicativeInverse(e,n);
            int cd = obj.pow(C, e, n2);
            return cd;
        }
    }
}
