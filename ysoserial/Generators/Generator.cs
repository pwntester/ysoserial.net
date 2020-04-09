using NDesk.Options;
using System;
using System.Collections.Generic;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    public interface Generator
    {
        string Name();
        string AdditionalInfo();
        string Credit();
        string Finders();
        string Contributors();
        List<string> Labels();
        List<string> SupportedFormatters();
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
        BridgeAndDerived = "Bridge and dervied",
        Mask = "It relies on other gadgets and is not a real gadget on its own (not really bridged or derived)", // We hide these in normal help as they are only valuable for research purposes - example is ResourceSet
        None="";
    }
}
