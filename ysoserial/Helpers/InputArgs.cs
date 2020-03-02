using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ysoserial.Helpers.CommandArgSplitter;

namespace ysoserial.Helpers
{
    class InputArgs
    {
        private string _cmdFullString;
        private string _cmdFileName;
        private string _cmdArguments;
        private string _cmdFromFile;
        private string _cmdRawNoEncoding;
        private bool _hasArguments;
        private CommandType _cmdType = CommandType.None;

        private bool _test = false;
        private bool _minify = false;
        private bool _useSimpleType = false;
        private bool _isRawCmd = false;
        
        public string CmdFullString
        {
            get
            {
                string tempFullCmd;
                
                if (IsRawCmd)
                {
                    tempFullCmd = this._cmdFullString;
                }
                else
                {
                    tempFullCmd = "cmd /c " + this._cmdFullString;
                }

                bool hasArgs;
                string[] splittedCmd = CommandArgSplitter.SplitCommand(tempFullCmd, this.CmdType, out hasArgs);

                this.CmdFileName = splittedCmd[0];

                this.HasArguments = hasArgs;

                if (hasArgs)
                {
                    this.CmdArguments = splittedCmd[1];
                }

                tempFullCmd = String.Join(" ", splittedCmd);

                return tempFullCmd;

            }

            set
            {
                _cmdFullString = value;
            }
        }

        public string CmdFileName
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdFileName;
                }
                else
                {
                    return "";
                }
                
            }

            private set
            {
                _cmdFileName = value;
            }
        }

        public string CmdArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _cmdArguments;
                }
                else
                {
                    return "";
                }
                
            }

            private set
            {
                _cmdArguments = value;
            }
        }

        public string CmdRawNoEncoding
        {
            get
            {
                return _cmdFullString;
            }
        }

        // this is when cmd is used to read from a file
        // return null if cmd is not a file
        public string CmdFromFile
        {
            get
            {
                if (File.Exists(_cmdFullString))
                {
                    Console.Error.WriteLine("Reading command from file " + _cmdFullString + " ...");
                    _cmdFromFile = File.ReadAllText(_cmdFullString);
                }
                else
                {
                    _cmdFromFile = null;
                }

                return _cmdFromFile;
            }

            set
            {
                _cmdFromFile = value;
            }
        }

        public bool Test
        {
            get
            {
                return _test;
            }

            set
            {
                _test = value;
            }
        }

        public bool Minify
        {
            get
            {
                return _minify;
            }

            set
            {
                _minify = value;
            }
        }

        public bool UseSimpleType
        {
            get
            {
                return _useSimpleType;
            }

            set
            {
                _useSimpleType = value;
            }
        }

        public bool IsRawCmd
        {
            get
            {
                return _isRawCmd;
            }

            set
            {
                _isRawCmd = value;
            }
        }

        public CommandType CmdType
        {
            get
            {
                return _cmdType;
            }

            set
            {
                _cmdType = value;
            }
        }

        public bool HasArguments
        {
            get
            {
                if (!CmdFullString.Equals(""))
                {
                    return _hasArguments;
                }
                else
                {
                    return false;
                }
                    
            }

            private set
            {
                _hasArguments = value;
            }
        }

    }
}
