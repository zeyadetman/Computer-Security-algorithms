using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            List<int> possibleKeys = new List<int>();
            char sec = cipherText[1];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == sec) possibleKeys.Add(i);
            }

            for (int i = 0; i < possibleKeys.Count; i++)
            {
                Console.WriteLine(possibleKeys[i].ToString());
                string s = Encrypt(plainText, possibleKeys[i]).ToLower();
                Console.WriteLine(cipherText + " " + s);
                if (String.Equals(cipherText, s))
                {
                    Console.WriteLine(possibleKeys[i]);
                    return possibleKeys[i];
                }
            }

            return -1;

        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int PTLength = (int) Math.Ceiling((double)cipherText.Length / key);
            return Encrypt(cipherText, PTLength).ToLower();

        }

        public string Encrypt(string plainText, int key)
        {
            String.Join(plainText,plainText.Split(' '));
            Console.WriteLine(plainText);
            List<List<char>> table = new List<List<char>>();
            int each = (int)Math.Ceiling((double)plainText.Length/key);
            int counter = 0;
            string CT = "";
            for (int i = 0; i < key; i++)
            {
                table.Add(new List<char>());
            }

            for (int i = 0; i < each; i++)
            {
                for (int j = 0; j < key && j<plainText.Length; j++)
                {
                    table[j].Add(plainText[counter]);
                    counter++;
                    if(counter == plainText.Length) break;
                }
            }

            for (int i = 0; i < table.Count; i++)
            {
                for (int j = 0; j < table[i].Count; j++)
                {
                    CT += table[i][j];
                }
            }
            return CT.ToUpper();
        }
    }
}