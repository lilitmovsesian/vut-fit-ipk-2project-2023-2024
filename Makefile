all: build clean

build: *.cs *.csproj
	dotnet publish --ucr -c Release -o .

clean:
	dotnet clean