import r2pipe
import json
import angr
import logging
from zeratool_1 import puts_model, printf_model, malloc_model
from .simgr_helper import hook_four,hook_execve,hook_win,get_win_regs,get_open_regs,get_write_regs
from angr import sim_options as so
import time
from pwn import*
import timeout_decorator
import claripy
import os
from .radare_helper import getRegValues, findShellcode, get_base_addr


log = logging.getLogger(__name__)

def check_is_win(binary_name,winFunctions):
    p = angr.Project(binary_name, load_options={"auto_load_libs": False})
    p.hook_symbol("system", get_win_regs())
    p.hook_symbol("execve", get_win_regs())
    p.hook_symbol("open", get_win_regs())
    p.hook_symbol("fopen", get_win_regs())
    for func_name,func in winFunctions.items():
        state = p.factory.call_state(addr = func['fcn_addr'])
        simgr = p.factory.simgr(state,save_unconstrained=True)
        try:
            @timeout_decorator.timeout(1200)
            def exploreBinary(simgr):#find(s)
                simgr.explore(find=lambda s: "type" in s.globals)

            exploreBinary(simgr)
            if "found" in simgr.stashes and len(simgr.found):
                return True
            else:
                return False
        except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
            log.info("[~] Overflow check timed out")
            print(simgr)
        # print(func_name,func['fcn_addr'])

def getWinFunctions(binary_name):

    winFunctions = {}

    # Initilizing r2 with with function call refs (aac)
    r2 = r2pipe.open(binary_name)
    r2.cmd("aaa")

    functions = [func for func in json.loads(r2.cmd("aflj"))]
    # print(functions)

    # Check for function that gives us system(/bin/sh)
    for func in functions:
        # print(func["name"])
        if "system" in str(func["name"]) or "execve" in str(func["name"]) or "fopen" in str(func["name"]) or "open" in str(func["name"]):
            tmp_name = func["name"]
            # print(tmp_name)

            # Get XREFs
            refs = [
                func for func in json.loads(r2.cmd("axtj @ {}".format(tmp_name)))
            ]
            # print(refs)
            for ref in refs:
                if "fcn_name" in ref:
                    winFunctions[ref["fcn_name"]] = ref
                    winFunctions[ref["fcn_name"]]['flags'] = 0
    print(winFunctions)
                    

    # Check for function that reads flag.txt
    # Then prints flag.txt to STDOUT
    known_flag_names = ["flag", "pass", "/bin/sh"]
    # print(known_flag_names )
    strings = [string for string in json.loads(r2.cmd("izj"))]
    for string in strings:
        value = string["string"]
        if any([x in value for x in known_flag_names]):
            address = string["vaddr"]
            # Get XREFs
            refs = [func for func in json.loads(r2.cmd("axtj @ {}".format(address)))]
            # print(refs)
            for ref in refs:
                if "fcn_name" in ref:
                    winFunctions[ref["fcn_name"]] = ref
                    winFunctions[ref["fcn_name"]]['flags'] = 1
    if check_is_win(binary_name,winFunctions):
        for k, v in list(winFunctions.items()):
            log.info("[+] Found win function {}".format(k))
        return winFunctions
    else:
        return {}

    # return winFunctions

