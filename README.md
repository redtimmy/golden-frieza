# golden-frieza

Imagine finding yourself in a “hostile” environment, one where you can’t run exploits, tools and applications without worrying about prying eyes spying on you, be they a legitimate system administrator, a colleague sharing an access with you or a software solution that scans the machine you are logged in to for malicious files. Your binary should live in encrypted form in the filesystem so that no static analysis would be possible even if identified and copied somewhere else. It should be only decrypted on the fly in memory when executed, so preventing dynamic analysis too, unless the decryption key is known.

To experiment with such an idea we have created the  “*golden frieza*” project. This repository contains some code examples working for ELF binaries. 

The full explanation about golden frieza (premises and usage) can be found on our [blog](https://www.redtimmy.com/red-teaming/blue-team-vs-red-team-how-to-run-your-encrypted-binary-in-memory-and-go-undetected/).

Periodically this repository will be updated with new methods and techniques when available.
