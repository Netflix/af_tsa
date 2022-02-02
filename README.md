# AF_TSA

af_tsa is a kernel module that's meant to allow for a TCP or UDP socket that can be
swapped out. Specifically, the swap it allows is for you to move the underlying "real socket"
from one network namespace to another. It does this by just wrapping the underlying socket.

# Development
## Building
To build the kernel module:

```
make kbuild
```

## Testing
To test the module (once loaded):

```
cd client
meson build
ninja -C build
sudo ./build/client
```

# Installation

The only supported platform is Ubuntu Bionic running a 5.10+ kernel.

```
curl -s https://packagecloud.io/install/repositories/netflix/titus/script.deb.sh | sudo bash
apt-get install -y af_tsa
```

## Caveats
af_tsa might have concurrency problems.
We try to mitigate this by being clever about our GC, and making sure we come to a stop point before GCing an sk.
The problem comes in when we swap the underlying sk.
We can't do an af_kcm kind of thing - because we'll all of the built-in kernel setsockopts (since those directly modify struct sock, and there's no way to make them cascade).

