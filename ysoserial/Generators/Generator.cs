using System;
using System.Collections.Generic;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    interface Generator
    {
        string Name();
        string Description();
        string Credit();
        string Finders();
        string Contributors();
        List<string> Labels();
        List<string> SupportedFormatters();
        object Generate(string formatter, InputArgs inputArgs);
        object GenerateWithNoTest(string formatter, InputArgs inputArgs);
        object Serialize(object payloadObj, string formatter, InputArgs inputArgs);
        Boolean IsSupported(string formatter);
    }

    // Discussion here: https://github.com/pwntester/ysoserial.net/pull/57#discussion_r381159793
    public static class GadgetTypes
    {
        public const string
        NotBridgeNotDerived = "Not bridge or derived", 
        NotBridgeButDervied = "Not bridge but derived", // Bridge has dervied meaning in it too
        BridgeAndDerived = "Bridge and dervied";
    }
}
