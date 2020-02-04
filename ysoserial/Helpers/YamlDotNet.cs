using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ysoserial.Helpers
{
    class YamlDotNet
    {
        public static String Minify(String xmlDocument)
        {
            xmlDocument = Regex.Replace(xmlDocument, "[\r\n]", "");
            xmlDocument = Regex.Replace(xmlDocument, @"\s+", " ");
            xmlDocument = Regex.Replace(xmlDocument, @"\s+\}", "}");
            xmlDocument = Regex.Replace(xmlDocument, @"\{\s+", "{");
            xmlDocument = Regex.Replace(xmlDocument, @",\s+", ",");
            return xmlDocument;
        }
    }
}
