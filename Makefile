all: build

build: *.cs *.csproj
	dotnet publish --ucr -c Release -o .