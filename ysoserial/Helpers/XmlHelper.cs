using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Xsl;

namespace ysoserial.Helpers
{
    public class XmlHelper
    {
        public static MemoryStream Minify(Stream xmlDocumentStream, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray)
        {
            return Minify(xmlDocumentStream, looseAssemblyNames, finalDiscardableRegExStringArray, FormatterType.None);
        }

        public static MemoryStream Minify(Stream xmlDocumentStream, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray, FormatterType formatterType)
        {
            return Minify(xmlDocumentStream, looseAssemblyNames, finalDiscardableRegExStringArray, formatterType, false);
        }

        public static MemoryStream Minify(Stream xmlDocumentStream, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray, FormatterType formatterType, Boolean useCDATA)
        {
            StreamReader reader = new StreamReader(xmlDocumentStream);
            string xmlDocument = reader.ReadToEnd();
            xmlDocument = Minify(xmlDocument, looseAssemblyNames, finalDiscardableRegExStringArray, formatterType, useCDATA);
            byte[] byteArray = Encoding.UTF8.GetBytes(xmlDocument);
            return new MemoryStream(byteArray);
        }

        public static String Minify(String xmlDocument, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray)
        {
            return Minify(xmlDocument, looseAssemblyNames, finalDiscardableRegExStringArray, FormatterType.None, false);
        }

        public static String Minify(String xmlDocument, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray, FormatterType formatterType)
        {
            return Minify(xmlDocument, looseAssemblyNames, finalDiscardableRegExStringArray, formatterType, false);
        }

        public static String Minify(String xmlDocument, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray, FormatterType formatterType, Boolean useCDATA)
        {
            xmlDocument = XmlParserNamespaceMinifier(xmlDocument);

            if (formatterType.Equals(FormatterType.SoapFormatter))
            {
                xmlDocument = SoapRefIdMinifier(xmlDocument);
            }else if (formatterType.Equals(FormatterType.NetDataContractXML))
            {
                xmlDocument = NetDataContractorIdMinifier(xmlDocument);
            }
            else if (formatterType.Equals(FormatterType.DataContractXML))
            {
                xmlDocument = DataContractorIdMinifier(xmlDocument);
            }

            xmlDocument = XmlXSLTMinifier(xmlDocument);
            xmlDocument = XmlDirtyMatchReplaceMinifier(xmlDocument, looseAssemblyNames, finalDiscardableRegExStringArray, useCDATA);

            return xmlDocument;
        }

        private static String XmlParserNamespaceMinifier(String xmlDocument)
        {
            Dictionary<string, string> namespaceLocalNames = new Dictionary<string, string>();

            // finding xmlns definitions
            string pattern = @"xmlns:([^=]+)\s*=\s*[""']([^""']*)[""']";
            Regex namespaceLocalNameRegEx = new Regex(pattern, RegexOptions.Compiled);
            MatchCollection matches = namespaceLocalNameRegEx.Matches(xmlDocument);

            foreach (Match match in matches)
            {
                // We need to ignore XMLNS in internal XML objects that are encoded or within CDATA
                Regex isNotInternalRegEx = new Regex(@"(?<!\<\!\[CDATA\[\s*)<[\w:.]+[^<>]+" + Regex.Escape(match.Value));

                if (isNotInternalRegEx.IsMatch(xmlDocument))
                {
                    GroupCollection groups = match.Groups;
                    String namespaceValue = groups[2].Value; 
                    if (Uri.UnescapeDataString(namespaceValue) != namespaceValue)
                    {
                        // URL decoding name spaces
                        string newNamespaceValue = Uri.UnescapeDataString(namespaceValue);
                        xmlDocument = Regex.Replace(xmlDocument, namespaceValue, newNamespaceValue);
                        namespaceValue = newNamespaceValue;
                    }
                    String namespaceLocalName = "";
                    if (namespaceLocalNames.TryGetValue(namespaceValue, out namespaceLocalName))
                    {
                        // replacing duplicate namespace localname and its usage
                        xmlDocument = ReplaceNamespaceNameAndValue(xmlDocument, groups[1].Value, namespaceLocalName);
                    }
                    else
                    {
                        namespaceLocalNames.Add(namespaceValue, groups[1].Value);
                    }
                }

            }

            // removing soap encodingStyle as it's not being used

            string encodingStylePattern = @"([^\s]+):encodingStyle\s*=\s*[""']";
            Regex encodingStyleRegEx = new Regex(encodingStylePattern, RegexOptions.Compiled);
            MatchCollection encodingStyleMatches = namespaceLocalNameRegEx.Matches(xmlDocument);

            foreach (Match match in encodingStyleMatches)
            {
                GroupCollection groups = match.Groups;
                String namespaceLocalName = groups[1].Value;

                var namespaceValue = namespaceLocalNames.FirstOrDefault(x => x.Value == namespaceLocalName).Key;

                if (namespaceValue != null && namespaceValue.Equals("http://schemas.xmlsoap.org/soap/envelope/"))
                {
                    // so encodingStyle is useless
                    xmlDocument = Regex.Replace(xmlDocument, namespaceLocalName + @":encodingStyle\s*=\s*[""'][^""']*[""']", "");
                }
            }

            // populating an array of A-Z
            String[] alpha = new String[26];
            int counter = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                alpha[counter] = c.ToString();
                counter++;
            }
            counter = 0;

            // replacing existing namespaces to make them shorter
            string fixedPrefix = "XmlParserNamespaceMinifier_";
            foreach (String namespaceLocalName in namespaceLocalNames.Values)
            {
                string newPrefix = fixedPrefix;
                if (Math.Abs(counter / 26) == 0)
                {
                    newPrefix += alpha[counter % 26].ToLowerInvariant();
                }
                else if (Math.Abs(counter / 26) == 1)
                {
                    newPrefix += alpha[counter % 26];
                }
                else
                {
                    newPrefix += alpha[counter % 26].ToLowerInvariant() + (counter - 52);
                }
                counter++;

                xmlDocument = ReplaceNamespaceNameAndValue(xmlDocument, namespaceLocalName, newPrefix);
            }
            xmlDocument = xmlDocument.Replace(fixedPrefix, "");
            return xmlDocument;
        }

        private static String ReplaceNamespaceNameAndValue(String xmlDocument, String OldName, String NewName)
        {
            // replacing duplicate namespace localname
            xmlDocument = Regex.Replace(xmlDocument, "xmlns:" + OldName + @"\s*=", "xmlns:" + NewName + "=");
            // Replacing the usage
            xmlDocument = Regex.Replace(xmlDocument, @"([\s/{<]+)" + OldName + ":", "$1" + NewName + ":");
            xmlDocument = Regex.Replace(xmlDocument, @"(=\s*[""'])" + OldName + ":", "$1" + NewName + ":");

            return xmlDocument;
        }


        private static String XmlDirtyMatchReplaceMinifier(String xmlDocument, String[] looseAssemblyNames, String[] finalDiscardableRegExStringArray, Boolean useCDATA)
        {
            // replacing spaces before > or /> in valid elements
            xmlDocument = Regex.Replace(xmlDocument, @"(\<\/?[\w\:_]+([\s/]+[a-zA-Z0-9\.\-\:=_]+\s*=\s*(""[^""]*""|'[^']*'))*)\s+(\/?>)", "$1$+");

            // replacing :nil="true" with :nil="1" as it does not matter in .NET
            xmlDocument = Regex.Replace(xmlDocument, @":(nil|boolean)\s*=\s*([""'])true[""']", ":$1=${2}1${2}");
            xmlDocument = Regex.Replace(xmlDocument, @":(nil|boolean)\s*=\s*([""'])false[""']", ":$1=${2}0${2}");

            // replacing spaces between things like:
            // Microsoft.IdentityModel, Version=3.5.0.0, PublicKeyToken=31bf3856ad364e35
            // clr-namespace:System.Diagnostics; assembly=system
            // {         x:Type      Diag:Process   }
            // Int32 Compare(System.String, System.String)
            xmlDocument = Regex.Replace(xmlDocument, @"([a-zA-Z0-9\.\-\:=_\s]+[;,]\s*)+([a-zA-Z0-9\.\-\:=_\s]+)[""'\]\<]", delegate (Match m) {
                // we do not want to remove spaces when two alphanumeric strings are next to each other
                String finalVal = m.Value;
                finalVal= Regex.Replace(finalVal, @"([^\w])[\s]+([\w])", "$1$2");
                finalVal = Regex.Replace(finalVal, @"([\w])[\s]+([^\w])", "$1$2");
                finalVal = Regex.Replace(finalVal, @"([^\w])[\s]+([^\w])", "$1$2");
                return finalVal;
            });

            xmlDocument = Regex.Replace(xmlDocument, @"([""'])\s*\{\s*([^&""'}\s]+)\s+([^&""'}\s]+)\s*\}\s*([""'])", "$1{$2 $3}$4");

            xmlDocument = Regex.Replace(xmlDocument, @"([""'])\s*\{\s*([^&""'}\s]+)\s*\}\s*([""'])", "$1{$2}$3");

            //xmlDocument = Regex.Replace(xmlDocument, @"([a-zA-Z0-9\.\-_]+\(([a-zA-Z0-9\.\-_]+\s*,)+\s*([a-zA-Z0-9\.\-_]+\s*)\))", delegate (Match m) { return m.Value.Replace(" ", ""); });

            // replacing not strong (loose) assembly names

            if (looseAssemblyNames != null)
            {
                foreach (String asmName in looseAssemblyNames)
                {
                    xmlDocument = Regex.Replace(xmlDocument, @"([""',=/>])\s*(" + asmName + @")([;,][a-zA-Z0-9\.\-\:=]+\s*)+([""'\]\<])", "$1$2$+");
                }
            }

            if (finalDiscardableRegExStringArray != null)
            {
                foreach (String dRegEx in finalDiscardableRegExStringArray)
                {
                    xmlDocument = Regex.Replace(xmlDocument, dRegEx, "");
                }
            }

            if (useCDATA)
            {
                // at this point, we want to decode all HTML encodings of valid XML elements and use CDATA
                // we assume we are not already in CDATA! (big assumption)
                // if we really want to save space, we need to have around 4 encoded values but we also ignore that for now

                string htmlEncodedPattern = @"(?<=>\s*)(\&lt;([\w\:_\-]+)[^<]+)(?=\s*<)";
                Regex htmlEncodedRegEx = new Regex(htmlEncodedPattern, RegexOptions.Compiled);
                MatchCollection htmlEncodedMatches = htmlEncodedRegEx.Matches(xmlDocument);

                foreach (Match match in htmlEncodedMatches)
                {
                    GroupCollection groups = match.Groups;
                    String htmlEncodedValue = groups[1].Value;
                    String newValue =  System.Web.HttpUtility.HtmlDecode(htmlEncodedValue);

                    // now we can also minify this probably
                    try
                    {
                        newValue = Minify(newValue, null, null);
                    }
                    catch (Exception e)
                    {
                        //
                    }

                    xmlDocument = xmlDocument.Replace(htmlEncodedValue, "<![CDATA[" + newValue + "]]>");
                    
                }
             
            }

            return xmlDocument;
        }


        public static String XmlXSLTMinifier(String xmlDocument)
        {
            XmlDocument minifiedXMLDoc = new XmlDocument();
            minifiedXMLDoc.LoadXml(xmlDocument);

            // by Soroush Dalili (@irsdl)
            // from various sources such as:
            //https://stackoverflow.com/questions/4593326/xsl-how-to-remove-unused-namespaces-from-source-xml
            //https://stackoverflow.com/questions/13974247/how-can-i-trim-space-in-xslt-without-replacing-repating-whitespaces-by-single-on

            String xsltDoc = @"<xsl:stylesheet version=""1.0""
 xmlns:xsl=""http://www.w3.org/1999/XSL/Transform"">
 <xsl:output omit-xml-declaration=""yes"" indent=""no""/>

<xsl:variable name=""whitespace"" select=""'&#09;&#10;&#13; '"" />

<!-- Strips trailing whitespace characters from 'string' -->
<xsl:template name=""string-rtrim"">
    <xsl:param name=""string"" />
    <xsl:param name=""trim"" select=""$whitespace"" />

    <xsl:variable name=""length"" select=""string-length($string)"" />

    <xsl:if test=""$length &gt; 0"">
        <xsl:choose>
            <xsl:when test=""contains($trim, substring($string, $length, 1))"">
                <xsl:call-template name=""string-rtrim"">
                    <xsl:with-param name=""string"" select=""substring($string, 1, $length - 1)"" />
                    <xsl:with-param name=""trim""   select=""$trim"" />
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select=""$string"" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:if>
</xsl:template>

<!-- Strips leading whitespace characters from 'string' -->
<xsl:template name=""string-ltrim"">
    <xsl:param name=""string"" />
    <xsl:param name=""trim"" select=""$whitespace"" />

    <xsl:if test=""string-length($string) &gt; 0"">
        <xsl:choose>
            <xsl:when test=""contains($trim, substring($string, 1, 1))"">
                <xsl:call-template name=""string-ltrim"">
                    <xsl:with-param name=""string"" select=""substring($string, 2)"" />
                    <xsl:with-param name=""trim""   select=""$trim"" />
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select=""$string"" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:if>
</xsl:template>

<!-- Strips leading and trailing whitespace characters from 'string' -->
<xsl:template name=""string-trim"">
    <xsl:param name=""string"" />
    <xsl:param name=""trim"" select=""$whitespace"" />
    <xsl:call-template name=""string-rtrim"">
        <xsl:with-param name=""string"">
            <xsl:call-template name=""string-ltrim"">
                <xsl:with-param name=""string"" select=""$string"" />
                <xsl:with-param name=""trim""   select=""$trim"" />
            </xsl:call-template>
        </xsl:with-param>
        <xsl:with-param name=""trim"" select=""$trim"" />
    </xsl:call-template>
</xsl:template>

<xsl:template match=""text()"">
  <xsl:call-template name=""string-trim"">
        <xsl:with-param name=""string"" select=""."" />
</xsl:call-template>
</xsl:template>

 <xsl:template match=""node()|@*"" priority=""-2"">
     <xsl:copy>
       <xsl:apply-templates select=""node()|@*""/>
     </xsl:copy>
 </xsl:template>

<xsl:template match=""comment()""/>

 <xsl:template match=""*"">
  <xsl:element name=""{name()}"" namespace=""{namespace-uri()}"">
   <xsl:variable name=""vtheElem"" select="".""/>

   <xsl:for-each select=""namespace::*"">
     <xsl:variable name=""vPrefix"" select=""name()""/>
<!--
Not sure why this one did not work so I had to change $vtheElem/descendant::* to //*
-->

<!--
     <xsl:if test=
      ""$vtheElem/descendant::* [namespace-uri() = current()     and
                   substring-before(name(),':') = $vPrefix or
                   @*[substring-before(name(),':') = $vPrefix] or
                   @*[contains(.,concat($vPrefix,':'))]
                  ]
      "">
-->
      <xsl:if test=
      ""//* [namespace-uri() = current()     and
                   substring-before(name(),':') = $vPrefix or
                   @*[substring-before(name(),':') = $vPrefix] or
                   @*[contains(.,concat($vPrefix,':'))]
                  ]
      "">
      <xsl:copy-of select=""."" />
     </xsl:if>
   </xsl:for-each>
   <xsl:apply-templates select=""node()|@*""/>
  </xsl:element>
 </xsl:template>
</xsl:stylesheet>";

            XslCompiledTransform transform = new XslCompiledTransform();

            transform.Load(new XmlTextReader(new StringReader(xsltDoc)));

            XmlWriterSettings settings = new XmlWriterSettings();

            settings.Indent = false;
            settings.NewLineHandling = NewLineHandling.None;
            settings.NewLineOnAttributes = false;
            settings.ConformanceLevel = ConformanceLevel.Document;
            settings.OmitXmlDeclaration = true;
            settings.NamespaceHandling = NamespaceHandling.OmitDuplicates;



            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (StreamReader reader = new StreamReader(memoryStream))
                {
                    using (XmlWriter writer = XmlWriter.Create(memoryStream, settings))
                    {
                        XmlReader xmlReadB = new XmlTextReader(new StringReader(minifiedXMLDoc.OuterXml));

                        transform.Transform(xmlReadB, null, writer);

                        memoryStream.Position = 0;

                        xmlDocument = reader.ReadToEnd();
                    }
                }
            }


            return xmlDocument;
        }


        private static String SoapRefIdMinifier(String xmlDocument)
        {

            string refIdPattern = @"id=""(ref\-\d+)""";
            Regex refIdRegEx = new Regex(refIdPattern, RegexOptions.Compiled);
            MatchCollection refIdMatches = refIdRegEx.Matches(xmlDocument);


            // populating an array of A-Z
            String[] alpha = new String[26];
            int counter = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                alpha[counter] = c.ToString();
                counter++;
            }
            counter = 0;

            foreach (Match match in refIdMatches)
            {
                GroupCollection groups = match.Groups;
                String refIdName = groups[1].Value;

                if (xmlDocument.Contains(@"href=""#" + refIdName + @""""))
                {
                    // refId is in use - it needs to be shortened
                    string newRefID = "";
                    if (Math.Abs(counter / 26) == 0)
                    {
                        newRefID = alpha[counter % 26].ToLowerInvariant();
                    }
                    else if (Math.Abs(counter / 26) == 1)
                    {
                        newRefID = alpha[counter % 26];
                    }
                    else
                    {
                        newRefID = alpha[counter % 26].ToLowerInvariant() + (counter - 52);
                    }
                    counter++;
                    // change
                    xmlDocument = xmlDocument.Replace(@"id=""" + refIdName + @"""", @"id=""" + newRefID + @"""");
                    xmlDocument = xmlDocument.Replace(@"href=""#" + refIdName + @"""", @"href=""#" + newRefID + @"""");
                }
                else
                {
                    // remove
                    xmlDocument = xmlDocument.Replace(@"id=""" + refIdName + @"""", "");
                }
                
            }

            return xmlDocument;
        }

        private static String NetDataContractorIdMinifier(String xmlDocument)
        {
            // the first tag can be shortened - we use the letter w here for no reason!
            string rootTagPattern = @"^\<([^\>\s""']+)";
            Regex rootTagRegEx = new Regex(rootTagPattern, RegexOptions.Compiled);
            string rootTag = rootTagRegEx.Match(xmlDocument).Groups[1].Value.Replace(".",@"\.");
            xmlDocument = Regex.Replace(xmlDocument, @"(\<\/?)" + rootTag + @"([\>\s""']+)", @"$1w$2");

            string refIdPattern = @"\:Id=""(\d+)""";
            Regex refIdRegEx = new Regex(refIdPattern, RegexOptions.Compiled);
            MatchCollection refIdMatches = refIdRegEx.Matches(xmlDocument);



            int counter = 0;

            foreach (Match match in refIdMatches)
            {
                GroupCollection groups = match.Groups;
                String refIdName = groups[1].Value;

                if (xmlDocument.Contains(@":Ref=""" + refIdName + @""""))
                {
                    counter++;
                    // change
                    xmlDocument = xmlDocument.Replace(@":Id=""" + refIdName + @"""", @":Id=""NetDataContractorIdMinifier_" + counter + @"""");
                    xmlDocument = xmlDocument.Replace(@":Ref=""" + refIdName + @"""", @":Ref=""NetDataContractorIdMinifier_" + counter + @"""");
                }
                else
                {
                    // remove
                    xmlDocument = Regex.Replace(xmlDocument, @"[^\s]+:Id=""" + refIdName + @"""", "");
                }

            }

            xmlDocument = xmlDocument.Replace("NetDataContractorIdMinifier_","");

            return xmlDocument;
        }

        private static String DataContractorIdMinifier(String xmlDocument)
        {

            string refIdPattern = @"\:Id=""ref(\d+)""";
            Regex refIdRegEx = new Regex(refIdPattern, RegexOptions.Compiled);
            MatchCollection refIdMatches = refIdRegEx.Matches(xmlDocument);



            int counter = 0;

            foreach (Match match in refIdMatches)
            {
                GroupCollection groups = match.Groups;
                String refIdName = groups[1].Value;

                if (xmlDocument.Contains(@":Ref=""ref" + refIdName + @""""))
                {
                    counter++;
                    // change
                    xmlDocument = xmlDocument.Replace(@":Id=""ref" + refIdName + @"""", @":Id=""NetDataContractorIdMinifier_" + counter + @"""");
                    xmlDocument = xmlDocument.Replace(@":Ref=""ref" + refIdName + @"""", @":Ref=""NetDataContractorIdMinifier_" + counter + @"""");
                }
                else
                {
                    // remove
                    xmlDocument = Regex.Replace(xmlDocument, @"[^\s]+:Id=""ref" + refIdName + @"""", "");
                }

            }

            xmlDocument = xmlDocument.Replace("NetDataContractorIdMinifier_", "");

            return xmlDocument;
        }

        public static string ConvertBytesToArrayOfUnsignedByteXML(byte[] input, string byteTag, string header, string footer)
        {
            var inputAsList = input.ToList();
            var result = SerializersHelper.XmlSerializer_serialize(inputAsList);
            result = Regex.Replace(result, @"<\?xml[^>]*>", header);
            result = Regex.Replace(result, @"</?ArrayOfUnsignedByte[^>]*>", footer);
            result = Regex.Replace(result, @"\s", "");
            if(!string.IsNullOrEmpty(byteTag))
            {
                result = result.Replace("unsignedByte", byteTag);
            }
            return result;
        }
    }
}
