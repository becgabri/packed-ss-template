# packed-ss-template
A repository for two basic packed secret sharing implementations. This is very much "research code". The main purpose of this is really just in case it can help people out with understanding how you can implement packed SS, sort of as a reference guide.

Some of the code provided here comes directly or with small modifications from [libscapi](https://github.com/cryptobiu/libscapi). See the LICENSES directory for more details.

## Dependencies
To run this code you will need a working version of [openssl](https://www.openssl.org/source/), [boost](https://www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html)(works with at least 1.71.0) and [ntl](https://libntl.org/download.html)(version >=11.0.0). Depending on your OS you may also need to install [GMP](https://gmplib.org/). You will also need [CMake](https://cmake.org/download/) with a version >=3.20.  


## Build Instructions 
After ensuring you have installed the necessary dependencies: 

```
// for a linux/unix system using apt for package management
sudo apt-get update
sudo apt-get install zlib1g-dev libgmp-dev
git clone https://github.com/becgabri/packed-ss-template.git
cd packed-ss-template
cmake .
make 
./MicroBench
```

## Other Info
There's some discussion about MPC, what packed secret sharing is, and the implementation itself in the [pdf](https://github.com/becgabri/packed-ss-template/blob/main/PackedSecretShareDoc.pdf) located in this repo. It also contains other resources that may be helpful. 

The two programs built are simply one to do benchmarking (called MicroBench) and then another that does testing (called PackedSSTest). In an ideal world, the testing would be done with a c++ test runner like google test or boost. However, as it's just a template, I've decided to leave it the way it is.  
