#:package Microsoft.CodeAnalysis.CSharp@5.9.0
#:property RootNamespace=Lint

using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Lint;

internal static class CSharpStyle
{
    private static readonly string[] TryPatternExceptions = ["FormatException", "OverflowException", "KeyNotFoundException"];
    private static readonly string[] FrameMethods = ["Update", "LateUpdate", "FixedUpdate"];
    private static readonly string[] RedrawMethods = ["OnGUI", "OnSceneGUI", "OnInspectorGUI"];
    private static readonly string[] CachedLookups = ["GetComponent", "GetComponents", "GetComponentInChildren", "GetComponentInParent", "PropertyToID", "StringToHash", "FindObjectOfType", "FindObjectsOfType"];
    private static readonly string[] LinqMethods = ["Where", "Select", "SelectMany", "OrderBy", "OrderByDescending", "ToList", "ToArray", "ToDictionary", "Any", "All", "First", "FirstOrDefault", "Last", "LastOrDefault", "Count", "Sum", "Min", "Max", "GroupBy", "Distinct", "Concat", "Skip", "Take"];
    private static readonly string[] MeshArrays = ["vertices", "normals", "tangents", "uv", "triangles", "colors", "colors32", "boneWeights"];
    private static readonly string[] ClockMembers = ["Now", "UtcNow", "Today"];
    private static readonly string[] RootFiles = ["global.json", "Directory.Build.props", ".editorconfig", ".gitattributes"];
    private static readonly string[] UnityFolders = ["Core", "Runtime", "Editor", "Tests/Editor"];

    static CSharpStyle()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, exception) => Console.Error.WriteLine(exception.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, exception) => Console.Error.WriteLine(exception.Exception);
    }

    private static int Main(string[] args) => Run(Path.GetFullPath(args.Length > 0 ? args[0] : "."), args.Length > 1 ? args[1] : null);

    private static int Run(string root, string? vendoredList)
    {
        List<string> tracked = ListTracked(root);
        string list = vendoredList ?? Path.Combine(root, ".github", "lint", "vendored-paths.txt");
        if (!File.Exists(list))
        {
            Console.Error.WriteLine(list + ": missing, install lint/common first");
            return 2;
        }

        (List<string> vendoredPrefixes, HashSet<string> vendoredNames) = ReadVendoredList(list);

        List<string> own = [.. tracked.Where(path => !IsVendored(path, vendoredPrefixes, vendoredNames))];
        bool isUnity = own.Exists(path => path.EndsWith(".asmdef", StringComparison.Ordinal)) || File.Exists(Path.Combine(root, "ProjectSettings", "ProjectVersion.txt"));
        List<string> packageRoots = isUnity ? FindPackageRoots(root, own) : [];
        List<string> findings = [];
        List<(string Path, SyntaxNode Root)> trees = [];
        foreach (string path in own.Where(path => path.EndsWith(".cs", StringComparison.Ordinal)))
        {
            string text = File.ReadAllText(Path.Combine(root, path));
            trees.Add((path, CSharpSyntaxTree.ParseText(text, path: path).GetRoot()));
            if (PackageRoot(path, packageRoots) is not null && !text.StartsWith("#nullable enable", StringComparison.Ordinal))
            {
                findings.Add($"{path}(1,1): CS-3 first line must be #nullable enable");
            }
        }

        HashSet<string> caught = [.. trees.SelectMany(tree => tree.Root.DescendantNodes().OfType<CatchDeclarationSyntax>()).Select(declaration => LastName(declaration.Type))];
        foreach ((string path, SyntaxNode tree) in trees)
        {
            bool isTest = path.Split('/').Any(segment => segment.EndsWith(".Tests", StringComparison.Ordinal) || segment is "Tests");
            bool isCore = path.Split('/').Any(segment => segment.EndsWith(".Core", StringComparison.Ordinal));
            CheckTypes(path, tree, caught, findings);
            CheckCatches(path, tree, findings);
            CheckStringLoops(path, tree, findings);
            if (isUnity)
            {
                CheckUnity(path, tree, findings);
            }
            else
            {
                CheckDotNet(path, tree, isTest, isCore, findings);
            }
        }

        if (isUnity)
        {
            CheckUnityLayout(root, own, packageRoots, findings);
        }
        else
        {
            CheckDotNetLayout(root, own, trees, findings);
        }

        foreach (string finding in findings)
        {
            Console.WriteLine(finding);
        }

        return findings.Count == 0 ? 0 : 1;
    }

    private static List<string> ListTracked(string root)
    {
        ProcessStartInfo start = new("git")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add("-C");
        start.ArgumentList.Add(root);
        start.ArgumentList.Add("ls-files");
        start.ArgumentList.Add("-z");
        using Process git = Process.Start(start) ?? throw new InvalidOperationException("git ls-files didn't start");
        string output = git.StandardOutput.ReadToEnd();
        git.WaitForExit();
        return git.ExitCode == 0
            ? [.. output.Split('\0', StringSplitOptions.RemoveEmptyEntries).Where(path => File.Exists(Path.Combine(root, path)))]
            : throw new InvalidOperationException($"git ls-files failed in {root}");
    }

    private static (List<string> Prefixes, HashSet<string> Names) ReadVendoredList(string list)
    {
        List<string> prefixes = [];
        HashSet<string> names = [];
        foreach (string raw in File.ReadLines(list))
        {
            string entry = raw.Trim();
            if (entry.StartsWith('/'))
            {
                prefixes.Add(entry.Trim('/') + "/");
            }
            else if (entry.Length > 0)
            {
                _ = names.Add(entry.Trim('/'));
            }
        }

        return (prefixes, names);
    }

    private static bool IsVendored(string path, List<string> prefixes, HashSet<string> names) =>
        prefixes.Exists(prefix => path.StartsWith(prefix, StringComparison.Ordinal)) || path.Split('/')[..^1].Any(names.Contains);

    private static List<string> FindPackageRoots(string root, List<string> own) =>
        [.. own.Where(path => path is "package.json" || path.EndsWith("/package.json", StringComparison.Ordinal))
            .Where(path => File.ReadAllText(Path.Combine(root, path)).Contains("\"unity\"", StringComparison.Ordinal))
            .Select(path => path[..^"package.json".Length])];

    private static string? PackageRoot(string path, List<string> packageRoots) =>
        packageRoots.Where(prefix => path.StartsWith(prefix, StringComparison.Ordinal)).OrderByDescending(prefix => prefix.Length).FirstOrDefault();

    private static string PackageName(string root, string package)
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, package + "package.json")));
        return manifest.RootElement.TryGetProperty("name", out JsonElement name) ? name.GetString() ?? string.Empty : string.Empty;
    }

    private static string LastName(TypeSyntax? type)
    {
        return type switch
        {
            QualifiedNameSyntax qualified => qualified.Right.Identifier.ValueText,
            SimpleNameSyntax simple => simple.Identifier.ValueText,
            null => string.Empty,
            _ => type.ToString(),
        };
    }

    private static void Add(List<string> findings, string path, SyntaxNode node, string rule, string message)
    {
        FileLinePositionSpan span = node.GetLocation().GetLineSpan();
        findings.Add($"{path}({span.StartLinePosition.Line + 1},{span.StartLinePosition.Character + 1}): {rule} {message}");
    }

    private static void CheckTypes(string path, SyntaxNode tree, HashSet<string> caught, List<string> findings)
    {
        foreach (TypeDeclarationSyntax type in tree.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            if (type is ClassDeclarationSyntax or StructDeclarationSyntax && type.ParameterList is not null)
            {
                Add(findings, path, type, "CS-10", $"{type.Identifier.ValueText} has a primary constructor; assign readonly fields in a constructor");
            }

            string baseName = LastName(type.BaseList?.Types.FirstOrDefault()?.Type);
            if (type is ClassDeclarationSyntax && baseName.EndsWith("Exception", StringComparison.Ordinal) && !caught.Contains(type.Identifier.ValueText))
            {
                Add(findings, path, type, "CS-11", $"{type.Identifier.ValueText} is never caught; throw a BCL exception instead");
            }
        }
    }

    private static void CheckCatches(string path, SyntaxNode tree, List<string> findings)
    {
        foreach (CatchClauseSyntax clause in tree.DescendantNodes().OfType<CatchClauseSyntax>())
        {
            if (TryPatternExceptions.Contains(LastName(clause.Declaration?.Type)))
            {
                Add(findings, path, clause, "CS-7", "use the Try method instead of catching " + LastName(clause.Declaration?.Type));
            }

            bool hasConditionalRethrow = clause.Block.Statements.OfType<IfStatementSyntax>()
                .Any(branch => branch.Statement.DescendantNodesAndSelf().OfType<ThrowStatementSyntax>().Any(statement => statement.Expression is null));
            if (hasConditionalRethrow)
            {
                Add(findings, path, clause, "CS-12", "use an exception filter (catch ... when) instead of a conditional throw;");
            }

            if (clause.Block.Statements.Count == 0)
            {
                Add(findings, path, clause, "CS-13", "empty catch");
            }
        }
    }

    private static void CheckStringLoops(string path, SyntaxNode tree, List<string> findings)
    {
        foreach (AssignmentExpressionSyntax assignment in tree.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.IsKind(SyntaxKind.AddAssignmentExpression) && IsStringExpression(assignment.Right) && IsInLoop(assignment))
            {
                Add(findings, path, assignment, "CS-18", "build strings in loops with StringBuilder");
            }
        }
    }

    private static bool IsStringExpression(ExpressionSyntax expression)
    {
        return expression switch
        {
            InterpolatedStringExpressionSyntax => true,
            LiteralExpressionSyntax literal => literal.IsKind(SyntaxKind.StringLiteralExpression),
            BinaryExpressionSyntax binary => binary.IsKind(SyntaxKind.AddExpression) && (IsStringExpression(binary.Left) || IsStringExpression(binary.Right)),
            _ => false,
        };
    }

    private static bool IsInLoop(SyntaxNode node)
    {
        foreach (SyntaxNode ancestor in node.Ancestors())
        {
            if (ancestor is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax or DoStatementSyntax)
            {
                return true;
            }

            if (ancestor is MemberDeclarationSyntax or LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax)
            {
                return false;
            }
        }

        return false;
    }

    private static void CheckUnity(string path, SyntaxNode tree, List<string> findings)
    {
        foreach (InvocationExpressionSyntax call in tree.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (call.Expression.ToString().StartsWith("Debug.Log", StringComparison.Ordinal)
                && call.ArgumentList.Arguments.Any(argument => argument.DescendantNodesAndSelf().OfType<MemberAccessExpressionSyntax>()
                    .Any(access => access.Name.Identifier.ValueText is "Message" && IsExceptionExpression(access.Expression))))
            {
                Add(findings, path, call, "CS-14", "log exceptions with Debug.LogException(ex, context)");
            }

            if (InvokedName(call) is "StartAssetEditing" && !HasStopInFinally(call))
            {
                Add(findings, path, call, "CS-15", "StartAssetEditing needs StopAssetEditing in a finally");
            }
        }

        foreach (MethodDeclarationSyntax method in tree.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            string name = method.Identifier.ValueText;
            bool isFrame = FrameMethods.Contains(name);
            if (isFrame || RedrawMethods.Contains(name))
            {
                CheckFrameBody(path, method, isFrame, findings);
            }
        }
    }

    private static bool IsExceptionExpression(ExpressionSyntax expression) => expression switch
    {
        ParenthesizedExpressionSyntax parentheses => IsExceptionExpression(parentheses.Expression),
        MemberAccessExpressionSyntax { Name.Identifier.ValueText: "InnerException" } inner => IsExceptionExpression(inner.Expression),
        IdentifierNameSyntax identifier => IsExceptionVariable(identifier),
        _ => false,
    };

    private static bool IsExceptionVariable(IdentifierNameSyntax identifier)
    {
        string name = identifier.Identifier.ValueText;
        foreach (SyntaxNode scope in identifier.Ancestors().TakeWhile(node => node is not TypeDeclarationSyntax).Where(IsVariableScope))
        {
            if (scope is ForEachStatementSyntax loop && string.Equals(loop.Identifier.ValueText, name, StringComparison.Ordinal))
            {
                return IsExceptionType(loop.Type);
            }

            foreach (SyntaxNode declaration in scope.DescendantNodes(node => node == scope || !IsVariableScope(node)))
            {
                switch (declaration)
                {
                    case CatchDeclarationSyntax caught when string.Equals(caught.Identifier.ValueText, name, StringComparison.Ordinal):
                        return true;
                    case ParameterSyntax parameter when string.Equals(parameter.Identifier.ValueText, name, StringComparison.Ordinal):
                        return IsExceptionType(parameter.Type);
                    case VariableDeclaratorSyntax { Parent: VariableDeclarationSyntax variable } local when string.Equals(local.Identifier.ValueText, name, StringComparison.Ordinal):
                        return IsExceptionType(variable.Type);
                    case SingleVariableDesignationSyntax pattern when string.Equals(pattern.Identifier.ValueText, name, StringComparison.Ordinal):
                        return pattern.Parent is DeclarationPatternSyntax typed && IsExceptionType(typed.Type);
                    default:
                        break;
                }
            }
        }

        return false;
    }

    private static bool IsExceptionType(TypeSyntax? type) =>
        LastName(type is NullableTypeSyntax nullable ? nullable.ElementType : type).EndsWith("Exception", StringComparison.Ordinal);

    private static bool IsVariableScope(SyntaxNode node) =>
        node is BlockSyntax or CatchClauseSyntax or BaseMethodDeclarationSyntax or LocalFunctionStatementSyntax
            or AnonymousFunctionExpressionSyntax or ForStatementSyntax or ForEachStatementSyntax or UsingStatementSyntax
            or SwitchSectionSyntax or SwitchExpressionArmSyntax or TypeDeclarationSyntax;

    private static void CheckFrameBody(string path, MethodDeclarationSyntax method, bool isFrame, List<string> findings)
    {
        string where = method.Identifier.ValueText;
        foreach (SyntaxNode node in method.DescendantNodes())
        {
            switch (node)
            {
                case InvocationExpressionSyntax call when CachedLookups.Contains(InvokedName(call)):
                    Add(findings, path, call, "CS-19", $"cache {InvokedName(call)} in a field, not in {where}");
                    break;
                case InvocationExpressionSyntax call when call.Expression is MemberAccessExpressionSyntax && LinqMethods.Contains(InvokedName(call)):
                    Add(findings, path, call, "CS-19", $"no LINQ in {where}");
                    break;
                case ArrayCreationExpressionSyntax or ImplicitArrayCreationExpressionSyntax or CollectionExpressionSyntax:
                    Add(findings, path, node, "CS-19", $"no new arrays in {where}");
                    break;
                case MemberAccessExpressionSyntax access when MeshArrays.Contains(access.Name.Identifier.ValueText) && access.Parent is not AssignmentExpressionSyntax:
                    Add(findings, path, access, "CS-19", $"{access.Name.Identifier.ValueText} copies the array on every read; read it once outside {where}");
                    break;
                case InterpolatedStringExpressionSyntax when isFrame:
                    Add(findings, path, node, "CS-19", $"no string building in {where}");
                    break;
                case BinaryExpressionSyntax binary when isFrame && binary.IsKind(SyntaxKind.AddExpression) && IsStringExpression(binary):
                    Add(findings, path, node, "CS-19", $"no string building in {where}");
                    break;
                default:
                    break;
            }
        }
    }

    private static string InvokedName(InvocationExpressionSyntax call)
    {
        return call.Expression switch
        {
            MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
            SimpleNameSyntax simple => simple.Identifier.ValueText,
            _ => string.Empty,
        };
    }

    private static bool HasStopInFinally(InvocationExpressionSyntax call)
    {
        static bool HasStop(TryStatementSyntax? attempt) =>
            attempt?.Finally?.Block.DescendantNodes().OfType<InvocationExpressionSyntax>().Any(stop => InvokedName(stop) is "StopAssetEditing") == true;

        StatementSyntax? statement = call.FirstAncestorOrSelf<StatementSyntax>();
        if (statement?.Parent is not BlockSyntax block)
        {
            return false;
        }

        int index = block.Statements.IndexOf(statement);
        bool isFollowedByTry = index + 1 < block.Statements.Count && HasStop(block.Statements[index + 1] as TryStatementSyntax);
        return isFollowedByTry || (block.Parent is TryStatementSyntax enclosing && enclosing.Block == block && HasStop(enclosing));
    }

    private static void CheckDotNet(string path, SyntaxNode tree, bool isTest, bool isCore, List<string> findings)
    {
        foreach (MethodDeclarationSyntax method in tree.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            bool isAsynchronous = LastName(method.ReturnType) is "Task" or "ValueTask";
            bool isExempt = isTest
                || method.Modifiers.Any(SyntaxKind.OverrideKeyword)
                || method.ExplicitInterfaceSpecifier is not null
                || method.Identifier.ValueText is "Main" or "DisposeAsync";
            bool hasToken = method.ParameterList.Parameters.Any(parameter => LastName(parameter.Type) is "CancellationToken");
            if (isAsynchronous && !isExempt && !hasToken)
            {
                Add(findings, path, method, "CS-6", $"{method.Identifier.ValueText} takes no CancellationToken");
            }
        }

        foreach (AttributeSyntax attribute in tree.DescendantNodes().OfType<AttributeSyntax>())
        {
            if (attribute.Parent is AttributeListSyntax { Target.Identifier.ValueText: "assembly" } && LastName(attribute.Name).StartsWith("InternalsVisibleTo", StringComparison.Ordinal))
            {
                Add(findings, path, attribute, "CS-22", "declare InternalsVisibleTo as an item in the csproj");
            }
        }

        if (!isCore)
        {
            return;
        }

        foreach (MemberAccessExpressionSyntax access in tree.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            if (access.Expression.ToString() is "DateTime" or "DateTimeOffset" && ClockMembers.Contains(access.Name.Identifier.ValueText))
            {
                Add(findings, path, access, "CS-23", "inject TimeProvider instead of reading the clock");
            }
        }
    }

    private static void CheckDotNetLayout(string root, List<string> own, List<(string Path, SyntaxNode Root)> trees, List<string> findings)
    {
        foreach (string required in RootFiles.Where(file => !own.Contains(file)))
        {
            findings.Add($"{required}(1,1): CS-24 missing at the repo root");
        }

        if (own.Count(path => !path.Contains('/', StringComparison.Ordinal) && path.EndsWith(".slnx", StringComparison.Ordinal)) != 1)
        {
            findings.Add("<App>.slnx(1,1): CS-24 the repo root holds exactly one .slnx");
        }

        if (own.Contains("global.json"))
        {
            using var global = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "global.json")));
            string? implicitPackage = FindSdkImplicitPackage(root, own);
            bool isPinned = global.RootElement.TryGetProperty("sdk", out JsonElement sdk)
                && sdk.TryGetProperty("version", out JsonElement version) && version.GetString()?.StartsWith("10.", StringComparison.Ordinal) == true
                && sdk.TryGetProperty("rollForward", out JsonElement roll)
                && (implicitPackage is null
                    ? roll.GetString() is "latestFeature"
                    : roll.GetString() is "disable" && version.GetString()?.Split('.') is ["10", string minor, string patch]
                        && minor.Length > 0 && minor.All(char.IsAsciiDigit) && patch.Length > 0 && patch.All(char.IsAsciiDigit));
            if (!isPinned)
            {
                findings.Add(implicitPackage is null
                    ? "global.json(1,1): CS-24 pin sdk.version 10.x with rollForward latestFeature"
                    : $"global.json(1,1): CS-24 packages.lock.json has {implicitPackage}; pin the exact SDK with rollForward disable");
            }
        }

        foreach (string project in own.Where(path => path.EndsWith(".csproj", StringComparison.Ordinal)))
        {
            var xml = XDocument.Load(Path.Combine(root, project));
            CheckProject(project, xml, findings);
            CheckEntryHooks(project, xml, trees, findings);
        }
    }

    private static string? FindSdkImplicitPackage(string root, List<string> own)
    {
        foreach (string path in own.Where(path => Path.GetFileName(path) is "packages.lock.json"))
        {
            using var packages = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, path)));
            if (!packages.RootElement.TryGetProperty("dependencies", out JsonElement dependencies))
            {
                continue;
            }

            foreach (JsonProperty framework in dependencies.EnumerateObject())
            {
                foreach (JsonProperty package in framework.Value.EnumerateObject())
                {
                    if (package.Name is "Microsoft.NET.ILLink.Tasks" or "Microsoft.DotNet.ILCompiler")
                    {
                        return package.Name;
                    }
                }
            }
        }

        return null;
    }

    private static string Property(XDocument xml, string name) => xml.Descendants(name).LastOrDefault()?.Value.Trim() ?? string.Empty;

    private static bool HasReference(XDocument xml, string package) =>
        xml.Descendants("PackageReference").Any(reference => ((string?)reference.Attribute("Include"))?.StartsWith(package, StringComparison.OrdinalIgnoreCase) == true);

    private static void CheckProject(string project, XDocument xml, List<string> findings)
    {
        string name = Path.GetFileNameWithoutExtension(project);
        string folder = project.Contains('/', StringComparison.Ordinal) ? project[..project.LastIndexOf('/')] : string.Empty;
        bool hasBenchmarks = HasReference(xml, "BenchmarkDotNet");
        string expected = name.EndsWith(".Tests", StringComparison.Ordinal) ? "tests/" : hasBenchmarks ? "benchmarks/" : "src/";
        if (!string.Equals(folder, expected + name, StringComparison.Ordinal))
        {
            findings.Add($"{project}(1,1): CS-24 belongs at {expected}{name}/{name}.csproj");
        }

        if (name.EndsWith(".Tests", StringComparison.Ordinal) && !HasReference(xml, "xunit"))
        {
            findings.Add($"{project}(1,1): CS-21 test projects use xUnit");
        }

        if (hasBenchmarks && !name.EndsWith(".Benchmarks", StringComparison.Ordinal))
        {
            findings.Add($"{project}(1,1): CS-16 benchmark projects are named <App>.Benchmarks");
        }

        if (Property(xml, "LangVersion").Length > 0)
        {
            findings.Add($"{project}(1,1): CS-24 leave LangVersion unset");
        }

        string framework = Property(xml, "TargetFramework");
        bool hasUserInterface = Property(xml, "UseWPF") is "true" || Property(xml, "UseWindowsForms") is "true";
        if (!framework.StartsWith("net10.0", StringComparison.Ordinal) || (name.EndsWith(".Core", StringComparison.Ordinal) && (framework is not "net10.0" || hasUserInterface)))
        {
            findings.Add($"{project}(1,1): CS-24 target net10.0 (Core projects plain net10.0 with no UI)");
        }
    }

    private static void CheckEntryHooks(string project, XDocument xml, List<(string Path, SyntaxNode Root)> trees, List<string> findings)
    {
        string name = Path.GetFileNameWithoutExtension(project);
        if (Property(xml, "OutputType") is not ("Exe" or "WinExe") || name.EndsWith(".Tests", StringComparison.Ordinal) || name.EndsWith(".Benchmarks", StringComparison.Ordinal))
        {
            return;
        }

        string prefix = project.Contains('/', StringComparison.Ordinal) ? project[..(project.LastIndexOf('/') + 1)] : string.Empty;
        List<string> hooks = [.. trees.Where(tree => tree.Path.StartsWith(prefix, StringComparison.Ordinal))
            .SelectMany(tree => tree.Root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            .Where(assignment => assignment.IsKind(SyntaxKind.AddAssignmentExpression))
            .Select(assignment => assignment.Left switch
            {
                MemberAccessExpressionSyntax access => access.Name.Identifier.ValueText,
                IdentifierNameSyntax name => name.Identifier.ValueText,
                _ => string.Empty,
            })];
        List<string> needed = ["UnhandledException", "UnobservedTaskException"];
        if (Property(xml, "UseWindowsForms") is "true")
        {
            needed.Add("ThreadException");
        }

        if (Property(xml, "UseWPF") is "true")
        {
            needed.Add("DispatcherUnhandledException");
        }

        foreach (string hook in needed.Where(hook => !hooks.Contains(hook)))
        {
            findings.Add($"{project}(1,1): CS-13 the entry point subscribes to {hook}");
        }
    }

    private static void CheckUnityLayout(string root, List<string> own, List<string> packageRoots, List<string> findings)
    {
        bool hasCore = false;
        foreach (string asmdef in own.Where(path => path.EndsWith(".asmdef", StringComparison.Ordinal)))
        {
            string? package = PackageRoot(asmdef, packageRoots);
            string relative = package is null ? asmdef : asmdef[package.Length..];
            string folder = relative.Contains('/', StringComparison.Ordinal) ? relative[..relative.LastIndexOf('/')] : string.Empty;
            hasCore |= folder is "Core";
            if (package is null || !PackageName(root, package).StartsWith("dev.whyknot.", StringComparison.Ordinal) || !UnityFolders.Contains(folder))
            {
                findings.Add($"{asmdef}(1,1): CS-25 asmdefs sit in Core, Runtime, Editor or Tests/Editor of a dev.whyknot.<name> package");
            }

            using var definition = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, asmdef)));
            JsonElement json = definition.RootElement;
            if (!(json.TryGetProperty("rootNamespace", out JsonElement space) && space.GetString()?.StartsWith("WhyKnot.", StringComparison.Ordinal) == true))
            {
                findings.Add($"{asmdef}(1,1): CS-25 rootNamespace is WhyKnot.<Name>");
            }

            bool isEditorOnly = json.TryGetProperty("includePlatforms", out JsonElement platforms) && platforms.ValueKind == JsonValueKind.Array
                && platforms.GetArrayLength() == 1 && platforms[0].GetString() is "Editor";
            if (folder is "Editor" or "Tests/Editor" && !isEditorOnly)
            {
                findings.Add($"{asmdef}(1,1): CS-25 includePlatforms is [\"Editor\"]");
            }

            if (folder is "Core" && !(json.TryGetProperty("noEngineReferences", out JsonElement engine) && engine.ValueKind == JsonValueKind.True))
            {
                findings.Add($"{asmdef}(1,1): CS-25 the Core asmdef sets noEngineReferences");
            }
        }

        bool hasHeadlessTests = own.Exists(path => path.StartsWith("headless/", StringComparison.Ordinal) && path.EndsWith(".Tests.csproj", StringComparison.Ordinal)
            && File.ReadAllText(Path.Combine(root, path)).Contains("\"NUnit\"", StringComparison.Ordinal));
        if (hasCore && !hasHeadlessTests)
        {
            findings.Add("headless(1,1): CS-21 the Core assembly is tested headless with NUnit in headless/<App>.Tests");
        }
    }
}
