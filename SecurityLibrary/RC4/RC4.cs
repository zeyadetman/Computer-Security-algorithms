using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool flag = false;
            if (plainText[1] == 'x' && plainText[0] == '0')
            {
                flag = true;
                string tmpP = "";
                for (int i = 2; i < plainText.Length; i+=2)
                {
                    tmpP += char.ConvertFromUtf32(Convert.ToInt32(plainText[i].ToString()+plainText[i+1].ToString(), 16));
                }
                plainText = tmpP;
            }

            if (key[0] == '0' && key[1] == 'x')
            {
                string tmpK = "";
                for (int i = 2; i < key.Length; i+=2)
                {
                    tmpK += char.ConvertFromUtf32(Convert.ToInt32(key[i].ToString()+key[i+1].ToString(), 16));
                }
                key = tmpK;
            }
            int[] S = new int[256];
            int[] T = new int[256];
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int tmp = S[i];
                S[i] = S[j];
                S[j] = tmp;
            }

            int a=0, l=0, k = 0;
            int plLength = plainText.Length;
            int t;
            
            string C = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                a = (a + 1) % 256;
                l = (l + S[a]) % 256;
                int tmp;
                tmp = S[a];
                S[a] = S[l];
                S[l] = tmp;
                t = (S[a] + S[l]) % 256;
                k = S[t];
                Console.WriteLine(plainText[i].ToString() + k.ToString());
                C += char.ConvertFromUtf32((plainText[i] ^ k));
            }

            if (flag)
            {
                C = string.Join("", C.Select(c => ((int)c).ToString("x2")));
                C = "0x" + C;
            }
            Console.WriteLine(C);
            return C;
        }
    }
}
