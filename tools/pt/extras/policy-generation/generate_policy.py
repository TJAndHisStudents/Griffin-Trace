import os
import re
import sys
import struct
import math

# Validate the input arguments
if len(sys.argv) < 3:
	print 'Griffin Policy Generator'
	print '========================'
	print 'usage: generate_policy.py binary fpt-results.txt\n'
	print 'optional flags:'
	print '\t-d for producing human-readable debug info'
	print '\t\texample: generate_policy.py -d binary fpt-results.txt'
	sys.exit(0)

# Set the default argument values
b_print_debug = False
binary_file   = sys.argv[-2]
fpt_file      = sys.argv[-1]

# Retrieve the argument values
# TODO: In the future, if we want to add more flags, we'll need to make
#	this solution a lot more robust so that we separate flags from actual input
if len(sys.argv) == 4:
	if (sys.argv[1] == '-d'):
		b_print_debug = True
	else:
		print 'Invalid program use.'
		sys.exit(0)


def get_symbols(filename):
	'''output: {"foo": 0x4003be, "bar": 0x40048f, ...}'''
	symbol_to_addr = {}
	for line in os.popen('readelf --wide -s %s' % filename).readlines():
		cols = line.split()
		if len(cols) != 8:
			continue
		if cols[3] != 'FUNC':
			continue
		if cols[6] == 'UND':
			continue
		sym = cols[7]
		addr = int(cols[1], 16)
		assert addr
		symbol_to_addr[sym] = addr
	return symbol_to_addr

def get_calls(filename):
	'''output: {"hash.c:322": (addr, size), ...}'''
	calls = {}
	for line in os.popen('objdump -d %s | grep "call.*\\*"' % filename).readlines():
		cols = line.split('\t')
		addr = int(cols[0][:-1], 16)
		size = len(cols[1].split())
		loc = os.popen('addr2line -e %s %x' % (filename, addr)).read().strip()
		loc = re.search(r'[^/]*$', loc).group(0)
		loc = loc.split()[0]
		if loc.endswith('?'):
			continue
		calls[loc] = (addr, size)
	return calls

def parse_fpt_result(filename):
	'''output: {"hash.c:322": ["foo", "bar"], ...}'''
	policy = {}
	targets = []
	loc = None
	for line in open(filename):
		line = line.strip()
		if not loc:
			if line.startswith('/'):
				cols = line.split(':')
				loc = ':'.join(cols[-2:])
				loc = re.search(r'[^/]*$', loc).group(0)
			continue
		if not line:
			policy[loc] = targets
			loc = None
			targets = []
			continue
		if line.startswith('===') or line.startswith('['):
			continue
		targets.append(line)
	return policy

def convert_policy(policy, calls, symbols):
	'''input: {"hash.c:322": ["foo", "bar"], ...}
	output: {0x400321: [0x4003be, 0x40048f], ...}'''
	new_policy = {}
	for k, v in policy.items():
		try:
			# a call* in fpt-result.txt may not be in the binary
			new_k = sum(calls[k])
			# a symbol in fpt-result.txt may not be defined locally
			new_v = [symbols[s] for s in v]
		except KeyError: # ignore this call site
			continue
		new_policy[new_k] = new_v
	return new_policy

# Notes on struct.pack - the first parameter, the format, describes both the
#	number of characters presented and number of arguments, each of which are
#	mapped one-to-one with each other.
# Q - unsigned long long, I - unsigned int
# Example: 'QII' <- first arg is 64 bits, represented as unsigned long long int,
#	second and third are 32 bits, represented as unsigned ints

def generate_output(policy):
	source, destination = 0, 0
	output = []
	rows = []
	cols = []
	addrs = list(set(policy.keys() + sum(policy.values(), [])))
	addrs.sort()
	
	if (b_print_debug):
		output.append('-- Number of addresses: ' + str(len(addrs)) + '\n')
	else:
		output.append(struct.pack('I', len(addrs)))

	for a in addrs:
		if a in policy.keys(): # source
			if (not b_print_debug):
				output.append(struct.pack('QII', a, 0, source))
			rows.append(a)
			source += 1
		else: # target
			if (not b_print_debug):
				output.append(struct.pack('QII', a, 1, destination))
			cols.append(a)
			destination += 1

	if (b_print_debug):
		output.append('-- # Sources: ' + str(source) + ', # Destinations: ' + str(destination) + '\n\n')
		output.append('-- Destinations:\n')

		# To print out the columns in the right order as the little-endian format
		#	of the policy matrix, we have to move around the columns to be in the
		#	correct order.

		# Pre-allocate the array
		# Then reverse the column orders for each set of 8 columns
		# At the last one, we have to reverse however many we have left
		cols_le_order = len(cols)*[None]
		leftover = len(cols)%8
		for i in range(len(cols)):
			if (len(cols)-leftover <= i):
				cols_le_order[(leftover-i%8) + int(i/8)*8 - 1] = cols[i]
			else:
				cols_le_order[(7-i%8) + int(i/8)*8] = cols[i]
		
		for col in cols_le_order:
			output.append(str(col) + ' ')

		output.append('\n\n-- # Rows: ' + str(len(rows)) + ', # Cols: ' + str(int(math.ceil(len(cols) / 8.0)) * 8) + '\n')
	else:
		output.append(struct.pack('II', len(rows), int(math.ceil(len(cols) / 8.0)) * 8))
	
	# actually build the matrix
	for call in rows:
		count = 0
		byte = 0

		if (b_print_debug):
			output.append(str(call) + ' ')

		for target in cols:
			if target in policy[call]:
				byte |= 1 << count
			count += 1
			if count == 8:
				if (b_print_debug):
					output.append(format(byte, '0>8b'))
				else:
					output.append(chr(byte))
				count = 0
				byte = 0
		if count:
			if (b_print_debug):
				output.append(format(byte, '0>' + str(count) + 'b') + '\n')
				#output.append(format(byte, '0>8b') + '\n')
			else:
				output.append(chr(byte))
	return ''.join(output)

if __name__ == '__main__':
	policy = parse_fpt_result(fpt_file)
	symbols = get_symbols(binary_file)
	calls = get_calls(binary_file)
	policy = convert_policy(policy, calls, symbols)
	output = generate_output(policy)

	if (b_print_debug):
		with open('%s-policy-debug.txt' % binary_file, 'w') as f:
			f.write(output)
	else:
		with open('%s-policy.bin' % binary_file, 'wb') as f:
			f.write(output)
