# Test zipping capabilities by unzipping

This test utilty allows to test an integrity of a generated zip file by showing its directory
and also extract its content. It is based on [tinyzip](https://github.com/lovasoa/tinyzip).
You need to copy *.7b* and *.rs* in the _tinyzip_ root directory and then execute `rb`.

## Dependencies
There is a list of dependencies:
- [libdeflater](https://github.com/libdeflater/libdeflater)
- [simcli](https://github.com/vernisaz/simcli)
- [simcolor](https://github.com/vernisaz/simcolor)

The dependencies should be built first.

## Another use of the test suite
Since the test utility is capable to extract zip content, it can be used on Windows where no 
CLI unzip utility by default. 