using System;
using System.Text;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    
    public static class SerTrace
    {
        internal static void InfoLog(params Object[] messages)
        {
            BCLDebug.Trace("BINARY", messages);
        }

        internal static void Log(params Object[] messages)
        {
            if (!(messages[0] is String))
                messages[0] = (messages[0].GetType()).Name + " ";
            else
                messages[0] = messages[0] + " ";
            BCLDebug.Trace("BINARY", messages);
        }
    }

    public static class BCLDebug
    {
        public static bool isLoggingEnabled = false; // This is to enable debugging in ysoserial.net - for developers not normal users!

        public static void Trace(String switchName, params Object[] messages)
        {
            if (!isLoggingEnabled)
            {
                return;
            }

            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < messages.Length; i++)
            {
                String s;
                try
                {
                    if (messages[i] == null)
                    {
                        s = "<null>";
                    }
                    else
                    {
                        s = messages[i].ToString();
                    }
                }
                catch
                {
                    s = "<unable to convert>";
                }
                sb.Append(s);
            }

            sb.Append(System.Environment.NewLine);
            Console.WriteLine(sb);
        }
    }
}
