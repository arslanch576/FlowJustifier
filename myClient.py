import socket, optparse

parser = optparse.OptionParser()
parser.add_option('-i', dest='ip', default='127.0.0.1')
parser.add_option('-p', dest='port', type='int', default=12345)
parser.add_option('-m', dest='msg', default='h')
(options, args) = parser.parse_args()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(options.msg, (options.ip, options.port) )
#if options.msg == "h":
#	print("sent normal request")
#else:
#	print("sent attacker request")
