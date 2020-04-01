using System;
using System.Reflection;

namespace ysoserial.Helpers
{
    public class BinaryMinifier
    {
        public static string FullTypeNameMinifier(string strFullTypeName, string strAssemblyName)
        {
            if (strAssemblyName == null || strFullTypeName == null)
                return strFullTypeName;

            // replacing spaces between things like:
            // Foo, Microsoft.IdentityModel, Version=3.5.0.0, PublicKeyToken=31bf3856ad364e35
            // clr-namespace:System.Diagnostics; assembly=system
            string strFullTypeName_noSpace = System.Text.RegularExpressions.Regex.Replace(strFullTypeName, @"([^\w])[\s]+([\w])", "$1$2");
            strFullTypeName_noSpace = System.Text.RegularExpressions.Regex.Replace(strFullTypeName_noSpace, @"([\w])[\s]+([^\w])", "$1$2");
            strFullTypeName_noSpace = System.Text.RegularExpressions.Regex.Replace(strFullTypeName_noSpace, @"([^\w])[\s]+([^\w])", "$1$2");


            string shortenedFullTypeName = System.Text.RegularExpressions.Regex.Replace(strFullTypeName_noSpace, @"\s*,\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Multiline);

            try
            {
                var asm = Assembly.Load(strAssemblyName);
                if (asm.GetType(shortenedFullTypeName) !=null)
                {
                    strFullTypeName = shortenedFullTypeName;
                }
                    
            }
            catch
            {
                strFullTypeName = strFullTypeName_noSpace;
            }

            return strFullTypeName;
        }

        public static string AssemblyOrTypeNameMinifier(string strInput)
        {
            if (strInput == null)
                return strInput;
            
            if (!System.Text.RegularExpressions.Regex.IsMatch(strInput, @"[,]\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}"))
            {
                // does not contain an assembly name
                return strInput;
            }

            bool isAssemblyString = false;
            if (System.Text.RegularExpressions.Regex.IsMatch(strInput, @"^[^,]+\s*[,]\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}$",System.Text.RegularExpressions.RegexOptions.IgnoreCase| System.Text.RegularExpressions.RegexOptions.Multiline))
            {
                isAssemblyString = true;
            }

            // replacing spaces between things like:
            // Microsoft.IdentityModel, Version=3.5.0.0, PublicKeyToken=31bf3856ad364e35
            // clr-namespace:System.Diagnostics; assembly=system
            string strInput_noSpace = System.Text.RegularExpressions.Regex.Replace(strInput, @"([^\w])[\s]+([\w])", "$1$2");
            strInput_noSpace = System.Text.RegularExpressions.Regex.Replace(strInput_noSpace, @"([\w])[\s]+([^\w])", "$1$2");
            strInput_noSpace = System.Text.RegularExpressions.Regex.Replace(strInput_noSpace, @"([^\w])[\s]+([^\w])", "$1$2");

            if(IsValid(strInput_noSpace, isAssemblyString))
            {
                strInput = strInput_noSpace;
            }
            

            string strInput_simpleAsm = System.Text.RegularExpressions.Regex.Replace(strInput, @"[,]\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Multiline);

            if (IsValid(strInput_simpleAsm, isAssemblyString))
            {
                strInput = strInput_simpleAsm;
            }else if (!isAssemblyString && strInput.Contains("mscorlib"))
            {
                // we know mscorlib can be used a lot
                string strInput_simpleCorlibAsm = System.Text.RegularExpressions.Regex.Replace(strInput, @"mscorlib\s*,\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}", "mscorlib", System.Text.RegularExpressions.RegexOptions.IgnoreCase| System.Text.RegularExpressions.RegexOptions.Multiline);

                if (IsValid(strInput_simpleCorlibAsm, isAssemblyString))
                    strInput = strInput_simpleCorlibAsm;
            }

            return strInput;
        }

        private static bool IsValid(string strInput, bool isAssemblyString)
        {
            bool result = false;

            if (isAssemblyString)
            {
                try
                {
                    if (Assembly.Load(strInput) != null)
                        result = true;
                }
                catch { }
            }
            else
            {
                try
                {
                    if (Type.GetType(strInput) != null)
                        result = true;
                }
                catch { }
                
            }

            return result;
        }

    }
}
