using System;
using System.Globalization;
using System.IO;

namespace ysoserial.Helpers.ModifiedVulnerableBinaryFormatters
{
    public static class Environment
    {
        public static String GetResourceString(string str)
        {
            return str;
        }

        public static String GetResourceString(String key, params Object[] values)
        {
            String s = GetResourceString(key);
            return String.Format(CultureInfo.CurrentCulture, s, values);
        }

        public static void GetResourceString(string str, out Object test)
        {
            test = str;
        }

        public static Exception GetResourceString(string str, Stream test)
        {
            return new Exception(str);
        }
    }
}
