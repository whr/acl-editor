acl-editor
==========
This is a port of the ACL Editor project by Keith Brown from the Security Briefs column
from March 2005
http://msdn.microsoft.com/en-us/magazine/cc163832.aspx
The original implementation uses the outdated old style managed extensions for C++.

The goal of this project is to use current CLI/C++ and VC2010.

The editor is contained in a mixed mode assembly that references the msvcrt libs. Therefore you get
separate 32 and 64 bit dlls.

