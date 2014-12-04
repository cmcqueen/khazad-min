khazad-min
==========

Minimal [Khazad][1] ([Wikipedia][2]) encryption.

For most applications, it makes more sense to use AES, since it is a well-known standard. Khazad might be useful for small embedded applications where a smaller encryption block size is desireable, e.g. for encrypting small radio messages.

This aims to be suitable for small embedded systems with limited RAM and ROM.

It includes on-the-fly key schedule calculation, for minimal RAM usage if required in a very RAM-constrained application.

It includes a smaller S-box implementation, for a very ROM-constrained application (where the 256-byte look-up table might be too big).

Testing
-------

This has had minimal testing, by inspection of encryption/decryption of one of the [test vectors][3].


[1]: http://www.larc.usp.br/~pbarreto/KhazadPage.html
[2]: http://en.wikipedia.org/wiki/KHAZAD
[3]: http://www.larc.usp.br/~pbarreto/khazad-tweak-test-vectors.zip
