# packed-ss-template
A repository for two basic packed secret sharing implementations. This is very much "research code" and written hastily by a non-SWE person. The main purpose of this is really just in case it can help people out with understanding how you can implement packed SS, sort of as a reference guide.

The code provided here depends on [libscapi](https://github.com/cryptobiu/libscapi). The main dependency, however, is actually [ntl](https://libntl.org/). You may need to change the CMakeLists.txt file to reflect where you have installed libscapi. 

There's some discussion about MPC, what packed secret sharing is, and the implementation itself in the pdf located in this repo. It also contains other resources that may be helpful. 

The two programs built are simply one to do benchmarking and then another that does testing. In an ideal world, the testing would be done with a c++ test runner like google test or boost. However, as it's just a template, I've decided to leave it the way it is.  
