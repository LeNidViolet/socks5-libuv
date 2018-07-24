# socks5-libuv
A socks5 proxy fork from [libuv](https://github.com/libuv/libuv/tree/v1.x/samples/) sample socks5-proxy
.

# Build
#### Cmake
* Download [libuv](https://github.com/libuv/libuv/tree/v1.x/) sources (branch [v1.x](https://github.com/libuv/libuv/tree/v1.x/)).
* Set libuv path to LIBUV_DIR in CMakeLists.txt
* mkdir build && cd build && cmake .. && make


# Usage
<pre>
<code>[-b address] [-h] [-p port] [-u username] [-w password]  
options:  
-b Bind to this address or hostname. Default 127.0.0.1  
-p Bind to this port number.  Default: 1080  
-u User name to connect proxy. Default: None  
-w Password to connect to proxy. Default: None  
If neither a username nor a password is provided, the proxy does not need to be authenticated</code>
</pre>

# TDOD
* <del>Udp support</del>
* Build && Test for other platform[Only mac for now]
* IPV6 test
* Multiple bind addresses test
* Dns cache

