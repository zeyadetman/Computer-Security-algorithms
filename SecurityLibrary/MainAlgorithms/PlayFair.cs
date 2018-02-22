using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public struct KOMatrices
    {
        public Dictionary<char, Tuple<int, int>> KM;
        public List<List<char>> OM;
    }

    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public HashSet<char> ModifiedKey(string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; // j removed
            HashSet<char> Mkey = new HashSet<char>();
            int keyLength = key.Length;
            for (int i = 0; i < keyLength; i++)
            {
                if (key[i] == 'j')
                {
                    Mkey.Add('i');
                }
                else
                {
                    Mkey.Add(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                Mkey.Add(alphabet[i]); // j not exist!
            }

            return Mkey;

        }

        public KOMatrices KOFunc(HashSet<char> Mkey)
        {
            Dictionary<char, Tuple<int, int>> KMatrix = new Dictionary<char, Tuple<int, int>>();
            List<List<char>> OMatrix = new List<List<char>>();
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                List<char> tmp = new List<char>();
                for (int j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        KMatrix.Add(Mkey.ElementAt(counter), new Tuple<int, int>(i, j));
                        tmp.Add(Mkey.ElementAt(counter));
                        counter++;
                    }
                }

                OMatrix.Add(tmp);
            }

            KOMatrices komatrix = new KOMatrices();
            komatrix.KM = KMatrix;
            komatrix.OM = OMatrix;

            return komatrix;
        }

        public string Decrypt(string cipherText, string key)
        {
            HashSet<char> Mkey = ModifiedKey(key);
            string CT = "";
            return "";
        }


        public string Encrypt(string plainText, string key)
        {
            string CT = "";

            HashSet<char> Mkey = ModifiedKey(key);
            KOMatrices KOkey = KOFunc(Mkey);
            for (int i = 0; i < plainText.Length - 1; i+=2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    i++;
                    plainText = plainText.Substring(0, i) + 'x' + plainText.Substring(i);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            int PTLength = plainText.Length;
            for (int i = 0; i < PTLength; i += 2)
            {
                char c1 = plainText[i], c2 = plainText[i + 1];
                if (KOkey.KM[c1].Item2 == KOkey.KM[c2].Item2) //same column
                {
                    CT += KOkey.OM[(KOkey.KM[c1].Item1 + 1) % 5][KOkey.KM[c1].Item2];
                    CT += KOkey.OM[(KOkey.KM[c2].Item1 + 1) % 5][KOkey.KM[c2].Item2];
                }
                else if (KOkey.KM[c1].Item1 == KOkey.KM[c2].Item1)//same row
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][(KOkey.KM[c1].Item2 + 1) % 5];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][(KOkey.KM[c2].Item2 + 1) % 5];
                }
                else
                {
                    CT += KOkey.OM[KOkey.KM[c1].Item1][KOkey.KM[c2].Item2];
                    CT += KOkey.OM[KOkey.KM[c2].Item1][KOkey.KM[c1].Item2];
                }
            }

            return CT.ToUpper();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}
