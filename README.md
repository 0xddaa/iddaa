# iddaa
idapython scripts, including feature as below:

1. Integrete IDA pro and gdb through idapython.
2. Identify the suspicious functions in binary by static analysis.
3. Improve to analyze CGC format.

## Install
- On Windows:
    1. Change `port` in `iddaa/idapython/rpcserver.py` to yours.
    2. Copy the file in **idapython** to the directory of IDA plugin.
      - You can execute **install.bat** if you installed IDA pro at `C:\Program Files (x86)\IDA 6.8\`.

- On Linux:
    1. `git clone https://github.com/0xddaa/iddaa.git ~/tools/iddaa`
    2. `echo "source ~/tools/iddaa/gdbscript/gdbinit" >> ~/.gdbinit`
    3. Change `HOST` and `PORT` in `iddaa/gdbscript/rpc.py` to yours.

## Features
### RPC Server
- Symbol Collector
    - Make **gdb** to be able to use symbols named in IDA pro
- Pseudo Code Collector
    - Show the pseudo code of function defined in IDA pro
- idapython RPC
    - Remote idapython script execute

### CGC Helper
- Revise syscall
    - Revise correct comment in IDA pro becuase CGC use different syscall number. 
- Automatic function naming
    - All CGC binary is static linked, stripped, and never use glibc.  
    Rename the function if identified the possible pattern.

### Why not XMLPRC?
There are obvious delay if using xmlrpc to execute idapython.  
Some functions, such as `idaapi.decompile`, will let IDA pro be stucked with no reason.  
If you know the solution, please tell me. Orz  

## Usage
### RPC Server
You can use this command in **gdb**:
- `get_ida_symbols`  
    Get all symbols named in IDA pro.
- `get_pseudo_code [function]`  
    Get the pseudo code of specified function.
- `get_local_type`  
    Get all local types defined in IDA pro
- `idapython [files]`  
    Execute file in ida pro and get result.  
- `idc|idaapi|idautils [code]`  
    The RPC wrapper of idapython. Show the cheatsheet with `idapython cheatsheet`.

```
idc MakeComm(addr, comment)
----------------------------------------
Add comment at specified address.
Ex: idc MakeComm(0x804ddaa, 'Soy Sauce')

idc SetColor(addr, what, color)
----------------------------------------
Set color for specified area
Ex: idc SetColor(0x0804ddaa, 1, 0xaabbcc) // address only
    idc SetColor(0x0804ddaa, 2, 0xaabbcc) // entire function
    idc SetColor(0x0804ddaa, 3, 0xaabbcc) // entire segment
```

### CGC Helper
- Revise syscall
    - Press `Shift + R` to revise the syscall comment
    - Execute `CGCHelper.revise_syscall(True)` in console if you want to change the function name together
