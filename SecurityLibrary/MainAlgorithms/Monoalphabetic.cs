using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public Dictionary<char, char> KeyDictionary(string key, string Operation)// O(1)
        {
            Dictionary<char, char> dic = new Dictionary<char, char>();
            Ceaser ceaser = new Ceaser();
            for (int i = 0; i < 26; i++)
            {
                if (Operation == "encrypt")
                    dic.Add(ceaser.alphabet[i], key[i]);
                else
                    dic.Add(key[i], ceaser.alphabet[i]);
            }
            return dic;
        }
        public string Analyse(string plainText, string cipherText) // O()
        {
            SortedDictionary<char, char> KeyTable = new SortedDictionary<char, char>();
            Dictionary<char, bool> alphaList = new Dictionary<char, bool>();
            int PTLength = plainText.Length;
            int CTLength = cipherText.Length;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < PTLength; i++) // O(N)
            {
                if (!KeyTable.ContainsKey(plainText[i])) { KeyTable.Add(plainText[i], cipherText[i]); alphaList.Add(cipherText[i], true); }
            }
            if (KeyTable.Count != 26) //O(1)
            {
                Ceaser obj = new Ceaser();
                string alphabet = obj.alphabet;
                for (int i = 0; i < 26; i++)
                {
                    if (!KeyTable.ContainsKey(alphabet[i]))
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (!alphaList.ContainsKey(alphabet[j]))
                            {
                                KeyTable.Add(alphabet[i],alphabet[j]);
                                alphaList.Add(alphabet[j], true);
                                j = 26;
                            }
                        }
                    }
                }
            }

            string key = "";
            foreach (var item in KeyTable) // O(1)
            {
                key += item.Value;
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key, "decrypt");
            cipherText = cipherText.ToLower();
            int CTLength = cipherText.Length;
            string PT = "";
            for (int i = 0; i < CTLength; i++) // O(N)
            {
                if (char.IsLetter(cipherText[i]))
                    PT += keyTable[cipherText[i]];
                else
                    PT += cipherText[i];
            }
            return PT;

        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> keyTable = KeyDictionary(key,"encrypt"); 
            int PTLength = plainText.Length;
            string CT = "";
            for (int i = 0; i < PTLength; i++) //O(N)
            {
                if (char.IsLetter(plainText[i]))
                    CT += keyTable[plainText[i]];
                else
                    CT += plainText[i];
            }

            return CT.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> CAlphaFreq = new Dictionary<char, int>();
            SortedDictionary<char, char> keyTable = new SortedDictionary<char, char>();
            cipher = cipher.ToLower();
            int CTLength = cipher.Length;
            string key = "";
            for (int i = 0; i < CTLength; i++)
            {
                if(!CAlphaFreq.ContainsKey(cipher[i]))
                {
                    CAlphaFreq.Add(cipher[i],0);
                }
                else
                {
                    CAlphaFreq[cipher[i]]++;
                }
            }

            CAlphaFreq = CAlphaFreq.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            int counter = 0;
            foreach (var item in CAlphaFreq)
            {
                keyTable.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }

            for (int i = 0; i < CTLength; i++)
            {
                key += keyTable[cipher[i]];
            }

            return key;
        }
    }
}
