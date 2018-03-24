using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int i = baseN, v = 0, d = 1;
            while (number > 0)
            {
                int t = i / number, x = number;
                number = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= baseN;
            v = (v < 0)?(v + baseN) % baseN:-1;
            return v;
        }
    }
}
