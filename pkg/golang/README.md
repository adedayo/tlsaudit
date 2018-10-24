# Codebase from golang TLS package

Note that the package _gotls_ comes from the golang _tls_ package. I have modified it to export some methods that I wanted to use, in order to hook into and have more control of the TLS handshake steps.

I also introduced a few trivial methods to make my life easier. I have marked areas where I changed or introduced something with comments such as below to help identify the changes

```golang
//--changed by dayo
//--introduced by dayo
```

All credit to the Go team who gave us an incredible language and TLS implementation! Thank you so much.

This code is released under BSD 3-Clause License, similar to the golang language, which is released under a BSD-style license.