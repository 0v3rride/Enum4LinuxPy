# Enum4LinuxPy
Everyone's favorite SMB/SAMBA/CIFS enumeration tool rewritten in everyone's favorite language.

## Why
The original Perl version has a number of outstanding issues that have been open for over a year and have not been addressed. This results in mangled output, errors, etc.

## Progress/Todo
* Parse NBT data into a human readable format.
* Add default junk values for username and password
  * Add flag for the option to pass null username and password values
  I noticed I wasn't able to enumerate shares on a Windows box during a HTB challenge if null values were used for the username and or password. However, simply giving the junk username root allowed me to enumerate data via smb and rpc to find an open share. Enum4linux experiences the same problem.

### **Credit for the original Perl version of Enum4Linux goes to Mark Lowe and Portcullis Labs.**
