@echo off
rem Builds a single self-contained InstallWalker.exe into .\publish
pushd "%~dp0"
dotnet publish src\InstallWalker\InstallWalker.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
popd
