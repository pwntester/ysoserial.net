using System;
using System.Collections.Generic;

namespace ysoserial.Generators
{
    interface Generator
    {
        string Name();
        string Description();
        List<string> SupportedFormatters();
        object Generate(string cmd, string formatter, Boolean test);
        object Serialize(object cmdobj, string formatter, Boolean test);
        Boolean IsSupported(string formatter);
    }
}
