# Rainbow Table Generator

- **Authors:**
    - **Hennen Cyril**
    - **Ishimwe Daniel**
    - **Gardeur Nicolas**
    - **Meunier Arnaud**

## Overview

Compatibility tested on: MacOS Sequoia (arm), Windows 11 (x86_64), Ubuntu 22.04 (Virtual Machine)

**Compatibility List**

| Device                               | Intrinsic SHA-256 with extensions* | Portable SHA-256 (Stephan Brumme)   |
|--------------------------------------|-------------------------|-------------------------------------|
| AMD Ryzen 7 PRO 7840U (x64)              | ✔️                      | ✔️                                  |
| 13th Gen Intel(R) Core(TM) i9-13900K (x64) | ✔️                      | ✔️                                  |
| VM 10 vCore (x64)                    | ❌                      | ✔️                                  |
| M3 Pro (arm)                         | ❌                      | ✔️                                  |
| M2 Pro (arm)                         | ❌                      | ✔️                                  |

*: Intel 11th-gen (Rocket Lake), AMD Zen, or later (a few exceptions) and ARMv8, or later (Extensions are optional license, check spec sheet). [Intrinsic SHA-256 with extensions on Github](https://github.com/voidxno/fast-recursive-sha256/tree/main)

## Initial Setup

Tailored for Ubuntu 22.04 (assuming a clean install without conflicts on the tools used in this guide).

Our project is configured for `g++` v11.X.X using the `C++20` standard.

### 1. Installing dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake g++
sudo apt install -y gcc-11 g++-11
```

### 2. Configuring g++ and the C++ toolchain

Assuming a fresh install of ubuntu 22.04 and an apt update

```bash
g++ --version
```

Should output:

```bash
g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Copyright (C) 2021 Free Software Foundation, Inc.
```

**If `g++` is not on version 11:**

```bash
sudo apt install g++-11
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100
sudo update-alternatives --config gcc
sudo update-alternatives --config g++
```

### 3. Pulling the repository

To pull the repository and start using it do as follow :

```bash
git clone https://gitlab.com/info-y115/rainbow-table.git
cd .\rainbow-table
```

If you prefer to pull using ssh do as follow :
```bash
git clone git@gitlab.com:info-y115/rainbow-table.git
cd .\rainbow-table
```

### 4. Compiling the project

To compile the project we first have to initialize the build configuration. We do so by running the `cmake` program on the root of our project's repository.

`Case 1:` If you are running this software on a machine directly **recommended**

```bash
cmake .
```

If successful should output:
```bash
username@username-478572:~/[project_dir]$ cmake .
-- Compiling for x86_64 architecture
-- Configuring done
-- Generating done
-- Build files have been written to: /home/username/[project_dir]

```

Or if you are using an arm based machine:
```bash
username@username-478573:~/[project_dir]$ cmake .
-- Compiling for ARM architecture
-- Configuring done
-- Generating done
-- Build files have been written to: /home/username/[project_dir]

```

`Case 2:` You are running this software on a VM or a machine which does not have access to SHA256 cpu extensions **not recommended** (see compatibility table)

```bash
cmake -DUSE_PORTABLE_SHA256=ON .
```

```bash
username@username-VirtualBox:~/[project_dir]$ cmake -DUSE_PORTABLE_SHA256=ON .
-- Using portable SHA256 implementation
-- Configuring done
-- Generating done
-- Build files have been written to: /home/username/[project_dir]

```

**Warning:** After setting this compiler option, any further use of `cmake .` will use that option, you need to toggle on/off accordingly.

**Recommendation:** use the native recursive sha256 bundled with the code instead of the portable one, you may expect a 3x-4x boost in performances.


Then to compile the executables `attack` and `rainbow`:

```bash
make -j$(nproc)
```

This will create the two executables needed.

## Usage

### [OPTIONAL] gen_passwd

This is the professor's code that generates a list of passwords and corresponding SHA256 hashes.

```bash
./gen_passwd [PASSWORD_COUNT] [MIN_PASSWORD_LENGTH] [MAX_PASSWORD_LENGTH] pwd.txt hashes.txt
```

Example:

```bash
./gen_passwd 100 4 4 pwd.txt hashes.txt
```

### Rainbow Table Generator

`./rainbow [CHAIN-LENGTH] [TABLE_SIZE] [MIN_PWD_LENGTH] OPTIONAL[MAX_PWD_LENGTH]`

Example:

`./rainbow 1000 700000000 6`

- [CHAIN-LENGTH]: Integer number of calculation performed
- [TABLE_SIZE]: Integer number of lines in the rainbow table.
- [MIN_PWD_LENGTH]: Integer Min Length of the passwords in that particular table
- OPTIONAL[MAX_PWD_LENGTH]: Integer Max Length of the passwords in that particular table

**OUTPUT**: rainbow_table_length6_thread_0 ... rainbow_table_length6_thread_31 (For 32 Logical threads)

**Behavior:**

- If only [MIN_PWD_LENGTH] is provided => The program will generate the files containing the rainbow table of [MIN_PWD_LENGTH] chars password.
- If [MIN_PWD_LENGTH] and [MAX_PWD_LENGTH] are provided => The program will generate multiple rainbow table starting with the one with [MIN_PWD_LENGTH] to [MAX_PWD_LENGTH]. By using the OPTIONAL[MAX_PWD_LENGTH], the program will not end under 12 hours because we are generating multiple rainbow table. The maximum time the program may take is calculated like this : ([MAX_PWD_LENGTH] - [MIN_PWD_LENGHT] + 1) * 12h; for a maximum of 60h ((10 - 6 + 1) * 12). 


### Rainbow Table Attack script

- Usage: `./attack [HASHES.txt] [CHAIN_LENGTH]`

- [HASHES.txt]: Location of Hashes.txt file generated by professor's `gen_passwd`
- [CHAIN_LENGTH]: Target chain length (it is the same value inputed in the rainbow table generator [CHAIN-LENGTH] arguments)

**OUTPUT:**

```txt
33b66c53994dfa456c0a1f04c0291a5233636d9ebfb71a60551d0a445956db26 : ?
7111fa16f1679248df45350d6e45ba46d825327fa169a7030057dc78324c9ab8 : a2a25q
0ff3ef706f4459f60d8e944206a41ead3ae8f12701177c7db28aafa925c1049a : ?

```

**Behavior:**

- We don't know target password length encoded in the hashes file so we start with the smallest password length's rainbow table and try until we reach all the rainbow tables we have.

### Complete examples

#### Physical Host

```bash
cmake -DUSE_PORTABLE_SHA256=OFF .
make -j$(nproc)

./gen_passwd 100 6 6 pwd.txt hashes.txt

./rainbow 1000 568002355 6
./attack hashes.txt 1000
```

#### Virtual Host (VM)

```bash
cmake -DUSE_PORTABLE_SHA256=ON .
make -j$(nproc)

./gen_passwd 100 6 6 pwd.txt hashes.txt

./rainbow 1000 568002355 6
./attack hashes.txt 1000
```
