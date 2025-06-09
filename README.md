# ErroxPerms

Errox perms is a program designed to gain NT AUTHORITY \ SYSTEM access from a basic Windows user. It does this through attacking services for a service binary replacement attack, where the service binary is replaced with a compiled C program designed to simply run CMD then the actual service file.

## How it works

Read my github website.

## How to use it

Simply run the file on the target device and it will handle the rest for you. However, if you want something other than the CMD shell you will have to put the binary data of the shell.c program into the main.rs's "custom_service_data" variable.
