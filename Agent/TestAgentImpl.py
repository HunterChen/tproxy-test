from TestAgent import TestAgent
from cPickle import Pickler, Unpickler
import socket, select, re
import types
import sys,os,time
import exceptions
import subprocess
import shlex
import signal
import string
import traceback

LOGGING = 1

def search_file(filename, search_path):
   file_found = 0
   paths = search_path.split(os.path.pathsep)
   for path in paths:
      if path and os.path.exists(os.path.join(path, filename)):
          return os.path.abspath(os.path.join(path, filename))
   return None


class TestAgentImpl(TestAgent):
    def __init__(self, input, output):
        self.input = input
        self.output = output
        self.exit_dispatch = 0
        self.handles = {}
        self.child_processes = []
        self.log_enabled = LOGGING
        if self.log_enabled:
                self.logfile = open('log','a')

    def __del__(self):
        self.input.close()
        self.output.close()
        self.__kill_children()
        if self.log_enabled:
                self.logfile.close()

    def log(self,msg):
        if self.log_enabled:
                self.logfile.write(msg+'\n')

    def supervise_start(self, command, env=None):
        args = shlex.split(command)
        
        if args[0][0] != '/':
            # not an absolute filename
            
            if args[0].find('/') >= 0:
                # relative path that has directory component, search it in the ZWA, /usr and / prefixes
                search_path = '/usr:/'
                if os.environ.has_key("ZWA_INSTALL_DIR"):
                    search_path = os.environ["ZWA_INSTALL_DIR"] + ':' + search_path
            else:
                # only binary name, search it in the PATH augmented with ZWA directories
                search_path = os.environ["PATH"]
                search_path = '/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:' + search_path
                if env and env.has_key("PATH"):
                    search_path = env["PATH"] + ':' + search_path
                if os.environ.has_key("ZWA_INSTALL_DIR"):
                    search_path = os.environ["ZWA_INSTALL_DIR"] + '/bin:' + os.environ["ZWA_INSTALL_DIR"] + '/sbin:' + search_path
        
        args[0] = search_file(args[0], search_path)
        if not args[0]:
            raise Exception("Error locating command to run: %s" % command)
        sp = subprocess.Popen(args, env=env)
        self.child_processes.append(sp)
        time.sleep(3)
        return sp.pid
        
    def supervise_end(self, pid):
        ndx = 0
        for child in self.child_processes:
            if child.pid == pid:
                # FIXME: on windows we need to use win32api.TerminateProcess as os.kill isn't available
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
                time.sleep(3)
                retries = 0
                while child.poll() == None and retries < 5:
                    retries += 1
                    time.sleep(1)
                
                if child.poll() == None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass
                    retries = 0
                    while child.poll() == None  and retries < 5:
                        retries += 1
                        time.sleep(1)
                
                if child.poll() != None:
                    del self.child_processes[ndx]
                    return child.poll()
                else:
                    raise Exception("Error killing supervised process")
            ndx += 1

    def __check_children(self):
        ndx = 0
        for child in self.child_processes:
            if child.poll():
                raise Exception("Supervised process exited prematurely, exit code: %d" % child.poll())

    def __kill_children(self):
        ndx = 0
        for child in self.child_processes:
            self.supervise_end(child.pid)
        
    def run(self, cmd):
        return os.system(cmd)

    def dispatch_command(self):
        cmd = Unpickler(self.input).load()
        self.log("command get: "+cmd[0])
        if not hasattr(self, cmd[0]) or type(getattr(self, cmd[0])) != types.MethodType:
            Pickler(self.output, 1).dump(None)
            self.output.flush()
    
        f = getattr(self, cmd[0])
        self.log("params: "+`cmd[1:]`)

        start = time.time()
        now = start

        try:
            self.__check_children()
            res = apply(f, cmd[1:])
        except Exception, e:
            res = 'Error: %s' % e
            traceback.print_exc(traceback, sys.stderr)
            self.log("Exception "+res)
            #self.exit_dispatch = 1

        self.log('waited: '+`'%.2f' % (now-start)`)
        self.log('result to send: '+`res`)
        Pickler(self.output, 1).dump(res)
        self.output.flush()
        if self.exit_dispatch:
            return 0
        else:
            return 1
    
    def socket(self, family, socktype):
        f = socket.socket(family, socktype)
        f.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket.IP_TRANSPARENT = 19
        f.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        self.handles[f.fileno()] = f
        return f.fileno()
    
    def bind(self, fd, local):
        f = self.handles[fd]
        f.bind(local)
            
    def listen(self, fd, backlog):
        f = self.handles[fd]
        f.listen(backlog)
    
    def accept(self, fd, timeout=30):
        f = self.handles[fd]
        a,qqq ,qqqq = self.select([f],[],[],timeout)
        if a != []:
                res = f.accept()
                newfd = res[0].fileno()
                self.handles[newfd] = res[0]
                return (newfd, res[1])
        else:
                raise Exception, 'no connection to accept'
    
    def connect(self, fd, remote):
        f = self.handles[fd]
        try:
                f.connect(remote)
        except:
                raise Exception, "can't connect"

    def select(self, r, w, x, timeout):
        return select.select(r, w, x, timeout)
            
    def read(self, fd, bufsize, timeout=5):
        f = self.handles[fd]
        self.log("in read: socket = "+`f`)
        a,qqq ,qqqq = self.select([f],[],[], timeout)
        if a != []:
                try:
                        ret = f.recv(bufsize)
                except Exception, e:
                        self.log("except. caught: " + `sys.exc_info()`)
                        if e[0] == 32:
                                ret = f.recv(bufsize)
                        else:
                                raise socket.error, e
                self.log('received:'+`ret`)
                return ret
        else:
                raise Exception, 'nothing to read'

    def readfrom(self, fd, bufsize, timeout=5):
        f = self.handles[fd]
        self.log("in read: socket = "+`f`)
        a,qqq ,qqqq = self.select([f],[],[], timeout)
        if a != []:
                ret = f.recvfrom(bufsize)
                self.log('received:'+`ret`)
                return ret
        else:
                raise Exception, 'nothing to read'



    def write(self, fd, chunk):
        f = self.handles[fd]
        return f.send(chunk)

    def writeto(self, fd, chunk, address):
        f = self.handles[fd]
        return f.sendto(chunk,address)

    def close(self, fd):
        self.log("closing conn. "+`fd`)
        f = self.handles[fd]
        f.close()
        del self.handles[fd]

    def iptables_save(self, family):
        if family == socket.AF_INET:
            cmd = "iptables-save"
        else:
            cmd = "ip6tables-save"
            
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        out = p.stdout.read()
        ret = ''
        while out:
            ret += out
            out = p.stdout.read()
        p.wait()
        return ret

    def iptables_restore(self, family, ruleset):
        if family == socket.AF_INET:
            cmd = "iptables-restore"
        else:
            cmd = "ip6tables-restore"
            
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        p.stdin.write(ruleset)
        p.stdin.close()
        p.wait()
        return p.returncode

    def quit(self):
        self.exit_dispatch = 1
        return None
