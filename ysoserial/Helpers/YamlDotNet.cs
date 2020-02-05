using System;
using System.Text.RegularExpressions;

// Coded by Soroush Dalili (@irsdl)
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
