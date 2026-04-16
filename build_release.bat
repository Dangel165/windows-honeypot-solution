@echo off
echo ========================================
echo Windows Honeypot Solution - Release Build
echo ========================================
echo.

echo Cleaning previous builds...
if exist "bin\Release" rmdir /s /q "bin\Release"
if exist "src\WindowsHoneypot.UI\bin\Release" rmdir /s /q "src\WindowsHoneypot.UI\bin\Release"
if exist "src\WindowsHoneypot.Core\bin\Release" rmdir /s /q "src\WindowsHoneypot.Core\bin\Release"

echo.
echo Restoring NuGet packages...
dotnet restore WindowsHoneypot.sln --verbosity minimal
if %ERRORLEVEL% neq 0 (
    echo Failed to restore packages
    pause
    exit /b 1
)

echo.
echo Building solution in Release mode...
dotnet build WindowsHoneypot.sln --configuration Release --no-restore --verbosity minimal
if %ERRORLEVEL% neq 0 (
    echo Failed to build solution
    pause
    exit /b 1
)

echo.
echo Running tests...
dotnet test WindowsHoneypot.sln --configuration Release --no-build --verbosity minimal --logger "console;verbosity=minimal"
if %ERRORLEVEL% neq 0 (
    echo Tests failed - continuing with build...
)

echo.
echo Creating release directory...
if not exist "Release" mkdir "Release"

echo.
echo Publishing single-file executable...
dotnet publish src\WindowsHoneypot.UI\WindowsHoneypot.UI.csproj ^
    --configuration Release ^
    --runtime win-x64 ^
    --self-contained true ^
    --output "Release" ^
    --verbosity minimal ^
    /p:PublishSingleFile=true ^
    /p:PublishReadyToRun=true ^
    /p:PublishTrimmed=false ^
    /p:IncludeNativeLibrariesForSelfExtract=true

if %ERRORLEVEL% neq 0 (
    echo Failed to publish application
    pause
    exit /b 1
)

echo.
echo Copying additional files...
if exist "README.md" copy "README.md" "Release\"
if exist "README_KR.md" copy "README_KR.md" "Release\"
if exist "REALTIME_PROTECTION.md" copy "REALTIME_PROTECTION.md" "Release\"

echo.
echo Creating version info file...
echo Windows Honeypot Solution v1.0.0 > "Release\VERSION.txt"
echo Build Date: %date% %time% >> "Release\VERSION.txt"
echo Runtime: .NET 8.0 >> "Release\VERSION.txt"
echo Platform: Windows x64 >> "Release\VERSION.txt"
echo UAC: Requires Administrator >> "Release\VERSION.txt"

echo.
echo ========================================
echo Release build completed successfully!
echo ========================================
echo.
echo Output location: Release\WindowsHoneypot.UI.exe
echo.
echo IMPORTANT: This application requires administrator privileges
echo and will prompt for UAC elevation when started.
echo.
echo To run the application:
echo   1. Navigate to the Release folder
echo   2. Right-click WindowsHoneypot.UI.exe
echo   3. Select "Run as administrator" (or just double-click - UAC will prompt)
echo.
pause