<div align="center">
  <img src="logo.png" />
</div>

</br>

[![Build Status](https://dev.azure.com/alvaro0284/ysoserial.net/_apis/build/status/pwntester.ysoserial.net?branchName=master)](https://dev.azure.com/alvaro0284/ysoserial.net/_build/latest?definitionId=1&branchName=master)

A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

## Description
ysoserial.net is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes this data, the chain will automatically be invoked and cause the command to be executed on the application host.

It should be noted that the vulnerability lies in the application performing unsafe deserialization and NOT in having gadgets on the classpath.

This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial)

## Disclaimer 
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related with any companies, including Project owner and contributors employers.

## Usage
```
$ ./ysoserial_frmv2.exe -h
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Available formatters:
        ActivitySurrogateSelectorFromFile (ActivitySurrogateSelector gadget by James Forshaw. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;./dlls/System.Windows.Forms.dll'.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ActivitySurrogateSelector (ActivitySurrogateSelector gadget by James Forshaw. This gadget ignores the command parameter and executes the constructor of ExploitClass class.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ObjectDataProvider (ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz)
                Formatters:
                        Xaml
                        Json.Net
                        FastJson
                        JavaScriptSerializer
                        YamlDotNet < 5.0.0

Available plugins:
        altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
        ApplicationTrust (Generates XML payload for the ApplicationTrust class)
        Clipboard (Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps)
        DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
        Resx (Generates RESX files)
        TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)

Usage: ysoserial_frmv2.exe [options]
Options:
  -p, --plugin=VALUE         the plugin to be used
  -o, --output=VALUE         the output format (raw|base64).
  -g, --gadget=VALUE         the gadget chain.
  -f, --formatter=VALUE      the formatter.
  -c, --command=VALUE        the command to be executed.
  -t, --test                 whether to run payload locally. Default: false
  -h, --help                 show this message and exit
```

*Note:* XmlSerializer and DataContractSerializer formatters generate a wrapper Xml format including the expected type on the "type" attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated xml based on how XmlSerializer gets the expected type in your case.

## Plugins
Ysoserial.Net can be used to generate raw payloads or more complex ones using a plugin architecture. To use plugins, use `-p <plugin name>` followed by the plugin options (the rest of ysoserial.net options will be ignored). 

For more help on plugin options use `-h` along with `-p <plugin name>`. 

## v2 Branch
v2 branch is a copy of ysoserial.net (15/03/2018) that has been changed to work with .NET Framework 2.0 by [irsdl](https://github.com/irsdl). Although this project can be used with applications that use .NET Framework v2.0, it also requires .NET Framework 3.5 to be installed on the target box as the gadgets depend on it. This problem will be resolved if new gadgets in .NET Framework 2.0 become identified in the future.

## Contributing
- Fork it
- Create your feature branch (`git checkout -b my-new-feature`)
- Commit your changes (`git commit -am 'Add some feature'`)
- Push to the branch (`git push origin my-new-feature`)
- Create new Pull Request

## Thanks
Special thanks to all contributors:
- [Oleksandr Mirosh](https://twitter.com/olekmirosh)
- [irsdl](https://github.com/irsdl)
- [JarLob](https://github.com/JarLob)
- [DS-Kurt-Boberg](https://github.com/DS-Kurt-Boberg)
- [mwulftange](https://github.com/mwulftange)
- [yallie](https://github.com/yallie)
- [paralax](https://github.com/paralax)

## Additional Reading
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video(demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type?](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
