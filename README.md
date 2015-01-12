khazad-min
==========

Minimal [Khazad][1] ([Wikipedia][2]) encryption.

For most applications, it makes more sense to use AES, since it is a well-known standard. Khazad might be useful for small embedded applications where a smaller encryption block size is desireable, e.g. for encrypting small radio messages.

This aims to be suitable for small embedded systems with limited RAM and ROM.

It includes optional on-the-fly key schedule calculation, for minimal RAM usage if required in a very RAM-constrained application. For systems with sufficient RAM, there is also encryption and decryption with a pre-calculated key schedule.

Normally the S-box implementation is by a simple 256-byte table look-up. An optional smaller S-box implementation is included for a *very* ROM-constrained application, where a 256-byte look-up table might be too big. This would only be expected to be necessary for especially tiny target applications, e.g. an automotive keyless entry remote.

Testing
-------

Test programs are included, which test the S-box implementation and encrypt and decrypt operations.

Encryption and decryption are tested against the official [test vectors][3]. The test vectors were parsed and converted to C data structures using a Python program.

When using autotools, run the tests via:

    make check

Most of the test vectors can be checked quickly, however the last set of vectors, set 4, involve 10<sup>8</sup> iterations of key schedule and encryption, so take some time to run.

License
-------

This code is released under the MIT license. See [`LICENSE.txt`][4] for details.


[1]: http://www.larc.usp.br/~pbarreto/KhazadPage.html
[2]: http://en.wikipedia.org/wiki/KHAZAD
[3]: http://www.larc.usp.br/~pbarreto/khazad-tweak-test-vectors.zip
[4]: LICENSE.txt
