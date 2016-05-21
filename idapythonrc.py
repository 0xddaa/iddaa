import sys
sys.path.append('E:\iddaa')
import iddaautils as utils
import iddaacgc as cgc

# start sync server
gdbsync = utils.GDBSync()
gdbsync.start()

# init cgc
cgchelper = cgc.CGCHelper()
