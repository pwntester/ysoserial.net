using System;
using NDesk.Options;

namespace ysoserial.Plugins
{
    interface Plugin
    {
        string Name();
        string Description();
        OptionSet Options();
        object Run(String[] args);
    }
}
