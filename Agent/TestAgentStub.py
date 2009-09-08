from TestAgent import TestAgent
from cPickle import Pickler, Unpickler
import types, traceback, sys, time, socket, subprocess

class TestRunException(Exception):
    pass

class RMIFile:
	def __init__(self, agent, fd):
		self.agent = agent
		self.fd = fd
		self.closed = 0
	
	def __del__(self):
		try:
			self.close()
		except (IOError, EOFError, TestRunException):
			pass

	def fileno(self):
		return self.fd

	def bind(self, local):
		return self.agent.send_command('bind', self.fd, local)
	
	def connect(self, remote):
		return self.agent.send_command('connect', self.fd, remote)
		
	def listen(self, backlog):
		return self.agent.send_command('listen', self.fd, backlog)

	def accept(self, timeout=None):
		res = self.agent.send_command('accept', self.fd, timeout)
		r = RMIFile(self.agent, res[0])
		return (r, res[1])

	def read(self, maxbytes=-1):
		a = self.agent.send_command('read', self.fd, maxbytes)
		return a

	def readfrom(self, maxbytes=-1):
		a = self.agent.send_command('readfrom', self.fd, maxbytes)
		return a

	def write(self, chunk):
		return self.agent.send_command('write', self.fd, chunk)
	
	def writeto(self, chunk, address):
		a = self.agent.send_command('writeto',self.fd, chunk, address)
		return a

	def close(self):
		if not self.closed:
			self.agent.send_command('close', self.fd)
			self.closed = 1

	def disconnected(self):
		return self.agent.send_command('disconnected', self.fd)

class TestAgentStub(TestAgent):
	def __init__(self, cmd, role):
		self.role = role
		self.output = None
		self.input = None
		self.impl = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
		self.output, self.input = self.impl.stdout, self.impl.stdin
		
	def send_command(self, *args):
		verb_string = 'to %s %s ' % (self.role, args,)
#		verbose('sendcommand args: '+`args`)
		Pickler(self.input, 1).dump(args)
		self.input.flush()
		res = Unpickler(self.output).load()
		verb_string = verb_string + '= %s' % (`res`,)
		#print(verb_string) >> sys.stderr
		if type(res) == types.StringType and res[:5] == 'Error':
			raise TestRunException(res)
		return res
		
        def iptables_save(self, family=socket.AF_INET):
                return self.send_command('iptables_save', family)

        def iptables_restore(self, family=socket.AF_INET, ruleset=""):
                return self.send_command('iptables_restore', family, ruleset)
	
	def socket(self, family, socktype):
		fd = self.send_command('socket', family, socktype)
		return RMIFile(self, fd)
	
	def select(self, r, w, x, timeout = None):
	
                r_no = map(lambda x: x.fileno(), r)
                w_no = map(lambda x: x.fileno(), w)
                x_no = map(lambda x: x.fileno(), x)
                (r_res, w_res, x_res) = self.send_command('select', r_no, w_no, x_no, timeout)
                
                r_obj = []
                for xx in r:
                    if xx.fileno() in r_res:
                        r_obj.append(xx)
                w_obj = []
                for xx in w:
                    if xx.fileno() in w_res:
                        w_obj.append(xx)
                x_obj = []
                for xx in x:
                    if xx.fileno() in x_res:
                        x_obj.append(xx)
                return (r_obj, w_obj, x_obj)
	
	def supervise_start(self, cmd):
	        return self.send_command('supervise_start', cmd)

	def supervise_end(self, pid):
	        return self.send_command('supervise_end', pid)
	
	def quit(self):
		self.send_command('quit')
