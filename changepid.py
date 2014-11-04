# changeid.py: Jim Jones (jjonesu@gmu.edu) 10/31/2014
# Volatility plugin to edit the PID of a process in a vmem file.
# Tested with VMWare snapshots and suspended VMs.
# For help: vol.[py\exe] changepid -h
# Put this file in the volatility plugins folder (for full version) or specify plugin location for standalone executable.
# Offset extraction derived from pool scanner for process objects by AAron Walters from volatility framework v2.4.

import volatility.utils as utils 
import volatility.commands as commands 
import struct
import volatility.plugins.common as common
import volatility.obj as obj
import volatility.poolscan as poolscan
import os
import urllib

# uncomment for debugging
#import pdb
#pdb.set_trace()
#

class PoolScanProcess(poolscan.PoolScanner):
    """Pool scanner for process objects"""

    def __init__(self, address_space, **kwargs):
        
        poolscan.PoolScanner.__init__(self, address_space, **kwargs)

        self.struct_name = "_EPROCESS"
        self.object_type = "Process"
        # this allows us to find terminated processes 
        self.skip_type_check = True
        self.pooltag = obj.VolMagic(address_space).ProcessPoolTag.v()
        size = 0x1ae # self.address_space.profile.get_obj_size("_EPROCESS")

        self.checks = [ 
                ('CheckPoolSize', dict(condition = lambda x: x >= size)),
                ('CheckPoolType', dict(paged = False, non_paged = True, free = True)),
                ('CheckPoolIndex', dict(value = 0)),
                ]

class ChangePid(common.AbstractScanCommand):
    """Find eprocess block for a specific process image name and change the PID"""

    scanners = [PoolScanProcess]
    
    def __init__(self, config, *args, **kwargs):
        common.AbstractScanCommand.__init__(self, config, *args, **kwargs)
        # private plugin options
        self._config.add_option("IMAGE_NAME",
                          default = None, type='string',
                          help = "Process image name to edit")
        self._config.add_option("NEW_PID",
                          default = None, type='int',
                          help = "New PID to assign to process")
        self._config.add_option("SECTOR_SIZE",
                          default = 512, type='int',
                          help = "Sector size in bytes on the *host* system")

    def calculate(self):
        if self._config.VIRTUAL:
            addr_space = utils.load_as(self._config)
        else:
            addr_space = utils.load_as(self._config, astype = 'physical')
        return self.scan_results(addr_space)

    def render_text(self, outfd, data):
        # check profile and set pid_offset in EPROCESS block accordingly
        if('WinXP' in self._config.profile):
            pid_offset = 132 # 132=84h for WinXP*
        elif('Win7' in self._config.profile):
            pid_offset = 180 # 180=B4h for Win7*
        else:
            raise RuntimeError("No PID offset for this profile; find it and edit the code...")

        # find eprocess block offset
        for eprocess in data:
            if(str(eprocess.ImageFileName)==self._config.IMAGE_NAME):
                eblock_offset = eprocess.obj_offset
                eblock_pid = str(eprocess.UniqueProcessId) # casting to a str sets eblock_pid to the value rather than the pointer (the pointed-to data changes)
                
        # edit the memory file
        memfile=urllib.unquote((self._config.location).split('///')[1])
        with open(memfile,'r+b') as fm:
            fm.seek(eblock_offset) # we're assuming the eprocess block will start on a sector boundary
            sector = fm.read(self._config.SECTOR_SIZE)
            new_pid_bytes = struct.pack('<L',self._config.NEW_PID) # int to little endian bytes
            new_sector = ''
            for i in range (0,self._config.SECTOR_SIZE): # python strings are immutable - can't change them in place, so building a new_sector from the old one with changes
                if(i==(pid_offset)):
                    new_sector+=(new_pid_bytes[0])
                elif(i==(pid_offset+1)):
                    new_sector+=(new_pid_bytes[1])
                elif(i==(pid_offset+2)):
                    new_sector+=(new_pid_bytes[2])
                elif(i==(pid_offset+3)):
                    new_sector+=(new_pid_bytes[3])
                else:
                    new_sector+=(sector[i])
            fm.seek(eblock_offset) # go back because we read sector_size bytes and moved the pointer
            fm.write(new_sector)
        print("\nChanged PID of process named "+self._config.IMAGE_NAME+" from "+eblock_pid+" to "+str(self._config.NEW_PID)+" at memfile offset "+str(eblock_offset+pid_offset)+".\n")
            
