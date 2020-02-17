using System;
using System.Collections.Generic;

namespace ysoserial.Generators
{
    interface Generator
    {
        string Name();
        string Description();
        string Credit();
        bool isDerived();
        List<string> SupportedFormatters();
        object Generate(string cmd, string formatter, Boolean test, Boolean minify, Boolean useSimpleType);
        object Serialize(object cmdobj, string formatter, Boolean test, Boolean minify);
        object Serialize(object cmdobj, string formatter, Boolean test, Boolean minify, Boolean useSimpleType);
        Boolean IsSupported(string formatter);
    }
}
