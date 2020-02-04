using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ysoserial.Helpers
{
    class CommandArgSplitter
    {
        public enum CommandType : ushort
        {
            None = 0,
            XML = 1,
            JSON = 2,
            YamlDotNet = 3,
            XMLinJSON = 4,
            JSONinXML = 5,
        }

        public static String[] SplitCommand(string cmd, CommandType cmdType, out Boolean hasArgs)
        {
            hasArgs = false;
            String[] result = SplitCommand(cmd);
            if (result.Length == 2) hasArgs = true;

            if (cmdType == CommandType.JSON)
            {
                // escape for JSON
                result[0] = result[0].Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("'", "\'");
                if (hasArgs)
                {
                    result[1] = result[1].Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("'", "\'");
                }
            }
            else if (cmdType == CommandType.XML)
            {
                // escape for XML
                result[0] = XmlString(result[0]);
                if (hasArgs)
                {
                    result[1] = XmlString(result[1]);
                }
            }
            else if (cmdType == CommandType.XMLinJSON)
            {
                // escape for XML
                result[0] = JsonString(XmlString(result[0]));
                if (hasArgs)
                {
                    result[1] = JsonString(XmlString(result[1]));
                }
            }
            else if (cmdType == CommandType.JSONinXML)
            {
                // escape for XML
                result[0] = XmlString(JsonString(result[0]));
                if (hasArgs)
                {
                    result[1] = XmlString(JsonString(result[1]));
                }
            }
            else if (cmdType == CommandType.YamlDotNet)
            {

                if (result[0].Contains("'"))
                {
                    result[0] = result[0].Replace("'", "''");
                    result[0] = "'" + result[0] + "'";
                }

                if (hasArgs && result[1].Contains("'"))
                {
                    result[1] = result[1].Replace("'", "''");
                    result[1] = "'" + result[1] + "'";
                }
            }

            return result;
        }

        public static string XmlString(string text)
        {
            XmlDocument _xmlDoc = new XmlDocument();
            var el = _xmlDoc.CreateElement("t");
            el.InnerText = text;
            return el.InnerXml;
        }

        public static string JsonString(string text)
        {
            return text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("'", "\'");
        }

        public static String[] SplitCommand(string cmd, out Boolean hasArgs)
        {
            hasArgs = false;
            String[] result = SplitCommand(cmd);
            if (result.Length == 2) hasArgs = true;
            return result;
        }

        public static String[] SplitCommand(string cmd)
        {
            String[] result = cmd.Split(new char[] { ' ' }, 2);
            return result;
        }

    }
}
