using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string alphabet = "abcdefghijklmnopqrstuvwxyz";

        public int letterNum(char letter) // O(1)
        {
            for (int i = 0; i < 26; i++)
            {
                if (letter == alphabet[i]) return i;
            }

            return -1;
        }
        public string Encrypt(string plainText, int key)
        {
            int PTLength = plainText.Length;
            string CT = "";
            for (int i = 0; i < PTLength; i++) // O(N)
            {
                if (char.IsLetter(plainText[i]))
                {
                    int letterIndx = ((key + letterNum(plainText[i]))%26);
                    CT += char.ToUpper(alphabet[letterIndx]);
                }
                else
                {
                    CT += plainText[i];
                }
            }

            return CT;

        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int CTLength = cipherText.Length;
            string PT = "";
            for (int i = 0; i < CTLength; i++) // O(N)
            {
                if (char.IsLetter(cipherText[i]))
                {
                    int letterIndx = ((letterNum(cipherText[i]) - key) % 26);
                    if(letterIndx < 0) letterIndx += 26;
                    PT += alphabet[letterIndx];
                }
                else
                {
                    PT += cipherText[i];
                }
            }

            return PT;
        }

        public int Analyse(string plainText, string cipherText) // O(1)
        {
            if (plainText.Length != cipherText.Length) return -1;
            int letterPN = letterNum(plainText[0]);
            int letterCN = letterNum(char.ToLower(cipherText[0]));

            return ((letterCN - letterPN) < 0) ? (letterCN - letterPN) + 26 : (letterCN - letterPN) % 26;
        }
    }
}
