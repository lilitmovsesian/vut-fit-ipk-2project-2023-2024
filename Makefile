all: build clean

build:
	dotnet publish -c Release -r linux-x64 /p:PublishSingleFile=true -o ./

clean:
	dotnet clean