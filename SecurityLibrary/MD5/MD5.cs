using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        static string ToBinaryString(Encoding encoding, string text)
        {
            return string.Join("", encoding.GetBytes(text).Select(n => Convert.ToString(n, 2).PadLeft(8, '0')));
        }
        public string GetHash(string text)
        {
            //step1
            text = "Hello World!";
            var textP = ToBinaryString(Encoding.UTF8, text);
            textP = textP.Length < 448 ? textP + '1' : textP;
            while (textP.Length <448)
            {
                textP += '0';
            }
            Console.WriteLine(textP);
            Console.WriteLine(textP.Length);
            
            //step2
            var bitsAdded = Convert.ToString(text.Length*8, 2);
            Console.WriteLine(text.Length*8);            
            Console.WriteLine(bitsAdded);
            textP += bitsAdded;
            while (textP.Length < 512)
            {
                textP += '0';
            }

            /*
            int j = 0;
            for (int i = 0; i < 512; i+=8)
            {
                Console.Write("arr["+j.ToString()+"]: ");
                Console.Write(textP[i].ToString()+textP[i+1].ToString()+textP[i+2].ToString()+textP[i+3].ToString()+textP[i+4].ToString()+textP[i+5].ToString()+textP[i+6].ToString()+textP[i+7].ToString()+"\n");
                j++;
            }
            */
 
            //step3
            string A = "01234567";
            string B = "89ABCDEF";
            string C = "FEDCBA98";
            string D = "76543210";


            

            return "";

        }
    }
}
