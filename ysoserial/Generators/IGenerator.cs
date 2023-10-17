using NDesk.Options;
using System;
using System.Collections.Generic;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public interface IGenerator
    {
        string Name();
        string AdditionalInfo();
        string Credit();
        string Finders();
        string Contributors();
        List<string> Labels();
        List<string> SupportedFormatters();
        string SupportedBridgedFormatter();
        object BridgedPayload { get; set; }
        object Generate(string formatter, InputArgs inputArgs);
        object GenerateWithInit(string formatter, InputArgs inputArgs);
        object GenerateWithNoTest(string formatter, InputArgs inputArgs);
        object Serialize(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithInit(object payloadObj, string formatter, InputArgs inputArgs);
        object SerializeWithNoTest(object payloadObj, string formatter, InputArgs inputArgs);
        Boolean IsSupported(string formatter);
        OptionSet Options();
        void Init(InputArgs inputArgs);
    }

    // Discussion here: https://github.com/pwntester/ysoserial.net/pull/57#discussion_r381159793
    public static class GadgetTypes
    {
        public const string
        NotBridgeNotDerived = "Not bridge or derived",
        NotBridgeButDervied = "Not bridge but derived", // Bridge has dervied meaning in it too
        BridgeAndDerived = "Bridge and derived",
        GetterChainAndDerived = "Chain of arbitrary getter call and derived gadget",
        GetterChainNotDerived = "Chain of arbitrary getter call and not derived gadget",
        Dummy = "It relies on other gadgets and is not a real gadget on its own (not bridged or derived either)", // We hide these in normal help as they are only valuable for research purposes - example is ResourceSet
        None = "";
    }

    public static class Formatters
    {
        public const string
        BinaryFormatter = "BinaryFormatter",
        LosFormatter = "LosFormatter",
        SoapFormatter = "SoapFormatter",
        NetDataContractSerializer = "NetDataContractSerializer",
        DataContractSerializer = "DataContractSerializer",
        FastJson = "FastJson",
        FsPickler = "FsPickler",
        JavaScriptSerializer = "JavaScriptSerializer",
        JsonNet = "Json.Net",
        SharpSerializerBinary = "SharpSerializerBinary",
        Xaml = "Xaml",
        XmlSerializer = "XmlSerializer",
        YamlDotNet = "YamlDotNet",
        None = "";
    }
}
