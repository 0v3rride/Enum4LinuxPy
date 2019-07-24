# Enum4LinuxPy
Everyone's favorite SMB/SAMBA/CIFS enumeration tool rewritten in python.

## Why
The original Perl version has a number of outstanding issues that have been open for over a year and have not been addressed. This results in mangled output, errors, etc.

## Progress
New flags added:
* -y and -q both obtain domain information about the domain controller if E4lPy is targeting one. Output from -q is less verbose than the -y option. The -y option will display basic information about the DC and the domain which includes the IP of the DC, the domain name, the DC site name and DC flags that tell you if the DC is a PDC, BDC, has DNS enabled, is a KDC, etc.
* -e will enumerate any privileges one has
* -z will enumerate any services running on the remote host (will most likely require privileged credentials)

Options for password spraying and brute forcing have also been added. When performing a password spray, the list of users will be gathered when E4LPy enumerates domain users and local users on the remote target host. Simply provide a password you want to spray with the list of users gathered (--spray July2019!). When bruteforcing, a username of your choice should be specified with the --brute <user> flag along with the absolute path to a wordlist to use (--wordlist <path/to/wordlist.txt>). Also available are --timeout <int seconds> and --randtimeout <int maxseconds>. For randtimeout, if you specify 120, then E4LPy will choose a random integer anywhere between 0 and 120 and wait after each time it submits a username and password for authentication to the target. 
  
## TODO
N/A

### **Credit for the original Perl version of Enum4Linux goes to Mark Lowe and Portcullis Labs.**
