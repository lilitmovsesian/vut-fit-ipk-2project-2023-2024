.PHONY: all build publish clean

all: publish clean

publish:
	dotnet publish -c Release --self-contained false -o . --nologo


clean: 
	dotnet clean
