# iddaa
idapython scripts, including feature as below:

1. Integrete IDA pro and gdb through idapython.
2. Identify the suspicious functions in binary by static analysis.
3. Improve to analyze CGC format.


## Install
1. Put all python scripts in IDA plugins directory.
2. `echo "source /path/of/gggdbinit" >> ~/.gdbinit` 

## Features
### iddaapro.py
- Symbol Collector
    - Use symbols named in IDA pro
    - `get_ida_symbols`  
        Get all symbols named in IDA pro.
- Pseudo Code Collector
    - Show the pseudo code of function defined in IDA pr
    - `get_pseudo_code [function]`  
        Get the pseudo code of specified function.
    - `get_local_type`  
        Get all local types defined in IDA pro
- idapython RPC
    - Remote idapython script execute

### iddaacgc.py
- Revise syscall
    - Revise correct comment in IDA pro becuase CGC use different syscall number. 
- Automatic function naming
    - All CGC binary is static linked, stripped, and never use glibc.  
    Rename the function if identified the possible pattern.

### Why not XMLPRC?
There are obvious delay if using xmlrpc to execute idapython.  
Some functions, such as `idaapi.decompile`, will let IDA pro be stucked with no reason.  
If you know the solution, please tell me. Orz  
