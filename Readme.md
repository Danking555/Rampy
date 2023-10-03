# Rampy
Rampy is a fast, simple and short Windows RAM file parser written in python and ready for extension.

## Features
- List all processes on the system
- Windows 10 RAM file support
- No pdb files are needed yet
- No dependencies needed

## Usage
First, you need to make sure that [Python3] is installed.  
Then, you run [Winpmem] on your local machine and extract the RAM file.  
And then you run Rampy, specifying the RAM file path.  
```sh
python3.exe rampy.py [path_to_ram_file]
```


## TODO
- Integrate pdb files parsing support
- Implement more fuzzing techniques for objects and offsets
- Add more artifacts and data encrichments
- Support VM memory parsing


## License

[MIT]



   [Winpmem]: <https://github.com/Velocidex/WinPmem>
   [Python3]: <https://www.python.org/downloads/>
   [MIT]: <https://choosealicense.com/licenses/mit/>
