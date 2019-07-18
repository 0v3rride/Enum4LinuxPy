# Enum4LinuxPy
Everyone's favorite SMB/SAMBA/CIFS enumeration tool rewritten in python.

## Why
The original Perl version has a number of outstanding issues that have been open for over a year and have not been addressed. This results in mangled output, errors, etc.

## Progress/Todo
I recently made some updates to the tool to allow for remote code execution via pypsexec. However, in order to do so, one would have to obtain credentials of a privileged user and the ADMIN$ share on the remote machine has to be accessible for it to copy the PAExec executable over to the target. There are some other requirements that need to be fulfilled in order for this to work which you can find [here](https://www.bloggingforlogging.com/2018/03/12/introducing-psexec-for-python/). 

I suspect that I could be able to use an open share on a remote host that one would find when listing shares with Enum4LinuxPy. I could build a list of shares that e4lpy has enumerated and tried to map that allow read and write access with current credentials being supplied that aren't DA or privileged creds. That or a share that is poorly configured that allows read and write access to it without the need for credentials. This way e4lpy could send the PAExec executable over that that particular share rather than the ADMIN$. This would obviously require modification of the pypsexec project.

This is just a hypothesis, however it would be pretty neat and scary if I could get it work. More testing will be required.

### **Credit for the original Perl version of Enum4Linux goes to Mark Lowe and Portcullis Labs.**
