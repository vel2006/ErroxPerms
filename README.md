# ErroxPerms

ErroxPerms, the one stop shop for NT AUTHORITY \ SYSTEM elivation from a local user.

## How it works

ErroxPerms is designed to attack Windows machienes and gain access to NT AUTHORITY \ SYSTEM through several methods, all of which are outlined below.

### MSI Installer

Within MSI installer configurations there is an option to always allow the instalation with no checks, meaning we could easily install a service that is designed to run a certain binary.

### UAC Bypass

Within Windows registry for UAC (User Access Control) there are two items that if enabled will allow for a user to gain local Administrator permissions, which once gained allows for the creation of services.

### Services and DLLs

Within every operating system, regardless of type if a path is not provided for a command or file a search will ensue to find the binary or path. In this case if the service will simply check for a DLL that is within it's own directory a passthrough DLL could be used to spoof the target service's associated DLL and gain it's permissions.

### Common Paths and Directory Permissions

It is well known that on Windows there are certain protected paths, some of these however could be editable if the current user has the allowed permissions. This could allow for the modification of a binary or DLL, while similar to the "Services and DLLs" attack this pertains to every system binary that would be important.

## How to use it

