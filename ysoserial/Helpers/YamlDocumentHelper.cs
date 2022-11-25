using System;
using System.Text.RegularExpressions;

namespace ysoserial.Helpers
{
    public class YamlDocumentHelper
    {
        public static String Minify(String yamlString)
        {
            yamlString = Regex.Replace(yamlString, "[\r\n]", "");
            yamlString = Regex.Replace(yamlString, @"\s+", " ");
            yamlString = Regex.Replace(yamlString, @"\s+\}", "}");
            yamlString = Regex.Replace(yamlString, @"\{\s+", "{");
            yamlString = Regex.Replace(yamlString, @",\s+", ",");
            return yamlString;
        }
    }
}
