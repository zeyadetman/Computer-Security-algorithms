using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            List<List<char>> table = new List<List<char>>();
            Dictionary<int, string> cip = new Dictionary<int, string>();
            string PT = "";
            cipherText = cipherText.ToLower();
            int columns = key.Count;
            int rows = (int)Math.Ceiling((double)cipherText.Length / columns);
            for (int i = 0; i < rows; i++)
            {
                table.Add(new List<char>());
            }
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    
                }
            }

            return "";
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int columns = key.Count;
            int rows = (int)Math.Ceiling((double)plainText.Length / columns);
            if (plainText.Length != rows * columns)
            {
                int x = (rows * columns) - plainText.Length;
                string appender = new string('x',x);
                plainText += appender;
            }
            List<List<char>> table = new List<List<char>>();
            Dictionary<int, string> cip = new Dictionary<int, string>();
            string CT = "";
            for (int i = 0; i < rows; i++)
            {
                table.Add(new List<char>());
            }

            int counter = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns && counter<plainText.Length; j++)
                {
                    table[i].Add(plainText[counter]);
                    counter++;
                }
            }

            for (int i = 0; i < columns; i++)
            {
                string tmp = "";
                for (int j = 0; j < rows; j++)
                {
                    tmp += table[j][i];
                    cip[key[i] ] = tmp;
                }
            }

            for (int i = 1; i <= cip.Count; i++)
            {
                CT += cip[i];
            }
            Console.WriteLine(CT);
            return CT.ToUpper();
        }
    }
}
