using System;
using NDesk.Options;

namespace ysoserial.Plugins
{
    public interface IPlugin
    {
        string Name();
        string Description();
        string Credit();
        OptionSet Options();
        object Run(String[] args);
    }
}
