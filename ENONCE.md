# SSD & WS  
## Homework: rainbow attack  
**Year**: 2023 - 2024  
**Author**: R. Absil  

The objective of this group (3-5 students) homework is to implement an attack on password tables with a rainbow table. The deadline is set on **October 15 at 23h59**.

### Minimal objectives

From a table of passwords stored as pairs "(login,hash)" with the help of some cryptographic function $H$, you must implement a rainbow attack.

For academic reasons (mainly simplicity):

- passwords are _not_ salted,
- passwords are stored after a single pass through the hash function,
- passwords are alphanumeric with a length at least 6 and at most 10,
- the hash function $H$ is SHA-256.

The choice of language is left to your discretion (but that choice is your responsibility). Should you use custom libraries, their code _must_ be open-source.

Please note that you must at least submit two scripts:

- a preprocessing script allowing to generate a "sufficiently large" rainbow table $RT$,
- an attack script allowing to exploit $RT$ in order to find passwords from their hashes.

In _no way_ are you allowed to submit the rainbow table $RT$, which can be quite large.

Should you find it useful, two scripts are provided for you:

- `gen-passwd`, generating passwords accepted by the policy, storing them in one text file, and their hashes in another file,
- `check-passwd`, checking whether passwords stored in one file match hashes stored in another file.

You can compile them using the commands:

```bash
g++ -o gen-passwd -std=XXX random.hpp sha256.cpp gen-passwd.cpp passwd-utils.hpp
g++ -o check-passwd -std=XXX random.hpp sha256.cpp check-passwd.cpp passwd-utils.hpp
