using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ysoserial.Helpers
{
    public class Debugging
    {
        public static void ShowErrors(InputArgs inputArgs, Exception err)
        {
            if (inputArgs.IsDebugMode)
            {
                Console.WriteLine(err.StackTrace);
            }
        }
    }
}
