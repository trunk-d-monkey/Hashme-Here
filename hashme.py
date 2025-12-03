# Python 3 - Hash files in current directory AND subdirectories.
# Author: Aaron Roberts
# Title: HashMe v1.4
# Version  v1.3
#		* Added exclusins for output files when hashing. 
# Version 1.4
#       * Added support for hashing a single file hashing and windows clipboard only hashing

# This should also work fine on Linux and Mac with a shell script 
# in place of the .bat file with similar contents as long as the files
# folder is in the system path.  
# hr is for Hash Reports and will has all pdf files EXCEPT the FPR file
# in the reports folder (for MSP Reports) and copy to the Windows 
# Clipboard.  

import platform
import sys
import os
import hashlib
import subprocess

s_version = '1.4'

# If "cb" for Hash Reports is used, interrupt to do this and exit
def cb_hash(ll_files):

	l_output = ''
	
	# ~ ls_file = ll_files[0]
	ll_output = [] # Empty list to hold output
	
	for lx in ll_files:
	
		# Set hashlibs - Create new for EACH loop otherwise it compounds
		if s_hash == 'md5': do_hash = hashlib.md5()
		if s_hash == 'sha256': do_hash = hashlib.sha256()
		if s_hash == 'sha1': do_hash = hashlib.sha1()
		
		chunk_size = 4096
		
		f = open(lx, 'rb')

		while chunk := f.read(chunk_size):
			do_hash.update(chunk)
		
		f.close()
		
		# Give the total in uppercase
		hs = do_hash.hexdigest().upper()
		
		# Remove the root path from the output
		lx = lx.replace(s_root + s_dir, '')
		
		ll_output.append(f'{lx} | {s_hash}:{hs}')
		
		f = None
	
	li_output = len(ll_output) # Number of files
	li_count = 0 # Counter to have \n in lines with additional files
	
	for lx in ll_output:
		if li_count > 0: l_output = l_output + '\n' + lx
		else: l_output = l_output + lx
		li_count += 1

	copy_to_clipboard(l_output)
	print(s_divider)
	print(l_output)
	print(s_divider)
	print('Output copied to the Windows clipboard for pasting into report')

		
# Get the list of files
def make_file_list(l_s_root):
	
	l_l_files = []

	for root, dirs, files in os.walk(l_s_root):
		for file in files:
			file_name = os.path.join(root, file)
			
			# Set exclusions for output files
			exclude_md5 = os.path.join(root, f'hashes_output_md5.{s_type}')
			exclude_sha1 = os.path.join(root, f'hashes_output_sha1.{s_type}')
			exclude_sha256 = os.path.join(root, f'hashes_output_sha256.{s_type}')
			
			# Ass the file to the list if it's not a named output file
			if file_name != exclude_md5 and file_name != exclude_sha1 and file_name != exclude_sha256:
				l_l_files.append(file_name)
	
	return l_l_files

# Hash the data and write it to a TSV file
def hash_files(l_l_files):
	
	if s_type == 'tsv':
		l_s_sep = '\t'
	elif s_type == 'txt':
		l_s_sep = ' | '
	elif s_type == 'csv': 
		l_s_sep = ','
	else: l_s_sep = '   '
	
	if b_single == False:
	
		# Open the output file
		l_output_file = os.path.join(s_root, f'hashes_output_{s_hash}.{s_type}')
		op = open(l_output_file, '+w', encoding='utf-16')
		# ~ opt = open(l_output_file_t, '+w', encoding='utf-8')
		# Write the column names
		op.write(f'FILE_NAME{l_s_sep}{s_hash.upper()}\n')
		
		chunk_size = 4096
		
		# Hash the files while printing output
		for l_item in l_l_files:
		
			# Set hashlibs - Create new for EACH loop otherwise it compounds
			if s_hash == 'md5': do_hash = hashlib.md5()
			if s_hash == 'sha256': do_hash = hashlib.sha256()
			if s_hash == 'sha1': do_hash = hashlib.sha1()
			
			# Remove the root path from the output
			x = l_item.replace(s_root + s_dir, '')
			
			# Print the file name on the screen
			print(f'FILE: {x}')
			
			# Open file for binary read
			f = open(l_item, 'rb')
			
			# Do it in chunks to make it do LARGE files easier
			while chunk := f.read(chunk_size):
				do_hash.update(chunk)
			
			# Also works as above but simpler, though longer
			# ~ while True:
				# ~ chunk = f.read(chunk_size)
				# ~ if not chunk:
					# ~ break
				# ~ do_hash.update(chunk)
				
			# Give the total in uppercase
			hs = do_hash.hexdigest().upper()
			# Print the has on screen
			print(f'{s_hash.upper()}: {hs}')
			# Write the file name and has to the TSV
			op.write(f'{x}{l_s_sep}{hs}\n')

			print(s_divider)
			
			# Close the file being read
			f.close()
		
		# Close the output file. 
		op.close()
	
	
	if b_single == True and s_file != None and s_file != '':
		
		# Open the output file
		l_output_file = os.path.join(s_root, f'{s_file}_{s_hash}.{s_type}')
		op = open(l_output_file, '+w', encoding='utf-16')
		# ~ opt = open(l_output_file_t, '+w', encoding='utf-8')
		# Write the column names
		op.write(f'FILE_NAME{l_s_sep}{s_hash.upper()}\n')
		
		chunk_size = 4096
		
		# Hash the files while printing output
		for l_item in l_l_files:
		
			# Set hashlibs - Create new for EACH loop otherwise it compounds
			if s_hash == 'md5': do_hash = hashlib.md5()
			if s_hash == 'sha256': do_hash = hashlib.sha256()
			if s_hash == 'sha1': do_hash = hashlib.sha1()
			
			# Remove the root path from the output
			x = l_item.replace(s_root + s_dir, '')
			
			# Print the file name on the screen
			print(f'FILE: {x}')
			
			# Open file for binary read
			f = open(l_item, 'rb')
			
			# Do it in chunks to make it do LARGE files easier
			while chunk := f.read(chunk_size):
				do_hash.update(chunk)
			
			# Also works as above but simpler, though longer
			# ~ while True:
				# ~ chunk = f.read(chunk_size)
				# ~ if not chunk:
					# ~ break
				# ~ do_hash.update(chunk)
				
			# Give the total in uppercase
			hs = do_hash.hexdigest().upper()
			# Print the has on screen
			print(f'{s_hash.upper()}: {hs}')
			# Write the file name and has to the TSV
		
			op.write(f'{x}{l_s_sep}{hs}\n')

			print(s_divider)
			
			# Close the file being read
			f.close()
		
		# Close the output file. 

		op.close()
	
	return l_output_file


def copy_to_clipboard(text):
    process = subprocess.Popen(["clip.exe"], stdin=subprocess.PIPE, shell=False)
    process.communicate(text.strip().encode("utf-16"))
	

# If "hr" for Hash Reports is used, interrupt to do this and exit
def hr_hash():

	l_reports = []
	l_len = 0
	l_output = ''
	
	l_files = os.listdir()
	
	# Make the list of report files for hashing
	for l_r in l_files:
		l_len = len(l_r)
		if l_r[l_len - 4:] == '.pdf' and l_r[l_len - 7:] != 'FPR.pdf':
			l_reports.append(l_r)
	
	l_hash = 'sha256'
	
	print(s_divider)
	
	for l_item in l_reports:
		do_hash = hashlib.sha256()
		f = open(l_item, 'rb')
		buff = f.read()
		do_hash.update(buff)
		hs = do_hash.hexdigest().upper()
		l_output = l_output + f'\n{l_item}\nSHA256: {hs}\n'
		
		f.close()
		f = None
		hs = None
		l_typehash = None
	
	copy_to_clipboard(l_output)
	print(l_output)
	print(s_divider)
	print('Output copied to the Windows clipboard for pasting into report')


# SET THE LISTS AND DICTIONARIES FOR ALLOWED ARGUMENTS
def get_arguments():
	
	l_error = False
	
	global s_hash
	global s_type
	global s_special
	global b_single
	global s_file
	
	d_arguments = {
	'sha256': 'hash',
	'sha1': 'hash',
	'md5': 'hash',
	'tsv': 'type',
	'csv': 'type',
	'txt': 'type',
	'cb':'special',
	'hr': 'special',
	'help': 'special',
	'instructions': 'special'
	}
	
	i_arg = len(sys.argv) # Get number of arguments
	
	i_arg_count = 0
	
	ls_file = '' # Single file in argument
	
	# Get the arguments with lower case for comparision and original for file name
	for h in range(1, i_arg):
		x = sys.argv[h].lower() # Assign the argument to a variable
		y = sys.argv[h] # This to get argument in original state for single file if assigned
		if x in d_arguments:
			v = d_arguments[x] # Get the matching type of the argument
		else: 
			v = '' # To avoid error of unassigned variable
			# ~ l_error = True
		
		if v == 'hash': s_hash = x
		elif v == 'type': s_type = x
		elif v == 'special': s_special = x
		else: s_file = y # If it's NOT in the dic, assign it to a file name, NOT lower case converted
		
		# Assign the global s_single for single file hash
		if s_file != '' and s_file != None: b_single = True
		else: s_single = False
		
		# If help is asked for then provide it and exit
		if s_special == 'help' or l_error == True:
			if s_platform == 'Windows': l_hr = ', hr (Win), cb (Win)'
			else: l_hr = ''
			print_help('help', l_hr)
			sys.exit()
			
		if s_special == 'instructions':
			if s_platform == 'Windows': l_hr = ', hr (Win),  cb (Win)'
			else: l_hr = ''
			print_help('instructions', l_hr)
			sys.exit()
		
		x = None
	
	print(f'hash:{s_hash}, type:{s_type}, special:{s_special}, file:{s_file}')
		
def print_help(l_to_print = 'help', l_instructions_hr = ''):

	# l_instructions_hr is for the Windows extras

	l_instructions = f'''
========================================================================
============ INSTRUCTIONS ==============================================
========================================================================
This uses Python's native hash library to hash the files in the folder
it is started from and all files in subfolders recursively.  It will 
store the hashes in a TSV file in the folder it is run in that can be
opened and the hashes copied and pasted elsewhere.  It will remove the 
full path so you only have the file names and subfolder paths.  

INSTRUCTIONS:
Make a folder and add it to your system path (suggested "C:\\Scripts"
where you can add additional scripts OR if you already have one it can
go there.  Place this file and the corresponding .bat file in that folder.
Linux users can usually put the .py and an shell script in ~/.local/bin.

Edit the .bat file to make sure you have the correct python executable
and full path to the python script.  

You can then run this in any folder by opening a command prompt
(Type "cmd" in the path bar and hit ENTER), then typing "hashme".
The default will be SHA256 to TXT format but if you want MD5 or SHA1 
just enter it as an argument (EX: hashme md5, hashme md5 tsv). The order
of the arguments does not matter.  

To has a single file, type or drag the file to the command line.  the 
LAST file listed will be the one hashed.  The has will be displayed and
a file with the same name and the hash format.txt will be created with
the file name and hash contained within. 

Valid hash formats are SHA256, MD5, SHA1{l_instructions_hr}.
Valid output formats are txt, tsv, csv
'''

	l_instructions_2 = '''
The argument "hr" is for "hash reports" which will hash all .PDF files
except those starting with "FPR" and then display the results and copy
the restults to the Windows clipboard to allow pasting into a document.

The argument "cb" is for "clip board" and will hash the items, display
them and place them on the Windows clipboard for pasting into a report
or other document.  Be carefull because it will overwrite whatever else
is on the clipboard when it finishes. 
'''

	l_help = f'''{s_divider}\n    HELP - HASH ME\n{s_divider}
Valid hashes: sha256, sha1, md5
Valid File Types: txt, tsv, csv
Other: help{l_instructions_hr}, instructions 
{s_divider}
Arguments for each type will use the LAST one given
{s_divider}'''

	if l_to_print == 'help': 
		print(l_help)
	elif l_to_print == 'instructions':
		print(l_instructions)
		if s_platform == 'Windows': # or s_platform == 'Linux':
			input('\nPress [ENTER] to continue')
			print(l_instructions_2)
		
		
# END FUNCTIONS ========================================================

s_divider = '------------------------------------------------------'

s_platform = platform.system()
# Linux: Linux
# Mac: Darwin
# Windows: Windows

# NEXT IS HASHING ALL RECURSIVE IN CURRENT DIRECTORY ==========================
print(f'Hashme Here v{s_version}')

s_root = os.getcwd()
print(f'Root Folder: {s_root}')

if s_platform == 'Linux' or s_platform == 'Darwin': s_dir = '/'
if s_platform == 'Windows': s_dir = '\\'

s_hash = 'sha256'
s_type = 'txt'
s_special = ''
b_single = False # Single file is True, all files is False
s_file = None # Default assignent of NO single file to hash

# Get the arguments for global variables. Order is irrelevant. 
get_arguments()

# For SINGLE file hash =======================================
# Check and make sure the file exists before trying to hash it
if b_single == True:
	if s_file != None:
		if os.path.exists(s_file) == False:
			print(f'File {s_file} does not exist!')
			sys.exit()

# If hr is specified
if s_special == 'hr' and s_platform == 'Windows' and b_single == False:
	hr_hash()
	sys.exit()

# Call making a list of the files
if b_single == False: l_files = make_file_list(s_root) # Make the list of all files
if b_single == True: l_files = [s_file] # Put single file in a list if ONE file being hashed.


# If cb is used
if s_special == 'cb' and s_platform == 'Windows':
	cb_hash(l_files)
	sys.exit()

print(s_divider)

# Call the hashing of the files
s_output_file = hash_files(l_files)

# Show the output file name
print(f'Hashing complete. Check {s_output_file} for data')
print()
