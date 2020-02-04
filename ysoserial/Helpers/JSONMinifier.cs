using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ysoserial.Helpers
{
    class JSONMinifier
    {
        public static String Minify(String jsonString, String[] LooseAssemblyNames, String[] finalDiscardableRegExStringArray)
        {
            /*
            xmlDocument = XmlParserNamespaceMinifier(xmlDocument);
            xmlDocument = XmlXSLTMinifier(xmlDocument);
            
            */

            jsonString = JSONNETMinifier(jsonString);
            jsonString = JSONDirtyMatchReplaceMinifier(jsonString, LooseAssemblyNames, finalDiscardableRegExStringArray);

            return jsonString;
        }

        private static String JSONDirtyMatchReplaceMinifier(String jsonString, String[] LooseAssemblyNames, String[] finalDiscardableRegExStringArray)
        {

            // replacing spaces between things like:
            // Microsoft.IdentityModel, Version=3.5.0.0, PublicKeyToken=31bf3856ad364e35
            // clr-namespace:System.Diagnostics; assembly=system
            //jsonString = Regex.Replace(jsonString, @"[""'](\s*[^,;""']+\s*[,;]\s*)+([^,;""']+\s*)[""']", delegate (Match m) { return m.Value.Replace(" ", ""); });

            jsonString = Regex.Replace(jsonString, @"([a-zA-Z0-9\.\-\:=_\s]+[;,]\s*)+([a-zA-Z0-9\.\-\:=_\s]+)[""'\]\<]", delegate (Match m) {
                // we do not want to remove spaces when two alphanumeric strings are next to each other
                String finalVal = m.Value;
                finalVal = Regex.Replace(finalVal, @"([^\w])[\s]+([\w])", "$1$2");
                finalVal = Regex.Replace(finalVal, @"([\w])[\s]+([^\w])", "$1$2");
                finalVal = Regex.Replace(finalVal, @"([^\w])[\s]+([^\w])", "$1$2");
                return finalVal;
            });

            // replacing not strong (loose) assembly names

            if (LooseAssemblyNames != null)
            {
                foreach (String asmName in LooseAssemblyNames)
                {
                    jsonString = Regex.Replace(jsonString, @"([""',=/])\s*(" + asmName + @")(\s*[,]\s*[^,""']+)+\s*([""'])", "$1$2$+");
                }
            }

            if (finalDiscardableRegExStringArray != null)
            {
                foreach (String dRegEx in finalDiscardableRegExStringArray)
                {
                    jsonString = Regex.Replace(jsonString, dRegEx, "");
                }
            }

            return jsonString;
        }
        private static String JSONNETMinifier(String jsonString)
        {
            using (StringWriter stringWriter = new StringWriter())
            using (JsonReader jsonReader = new JsonTextReader(new StringReader(jsonString)))
            using (JsonWriter jsonWriter = new JsonTextWriter(stringWriter))
            {
                jsonWriter.Formatting = Formatting.None;
                jsonWriter.WriteToken(jsonReader);
                jsonString = stringWriter.ToString();
            }

            return jsonString;
        }
    }
}
