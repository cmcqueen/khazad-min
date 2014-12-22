khazad-min
==========

Minimal [Khazad][1] ([Wikipedia][2]) encryption.

For most applications, it makes more sense to use AES, since it is a well-known standard. Khazad might be useful for small embedded applications where a smaller encryption block size is desireable, e.g. for encrypting small radio messages.

This aims to be suitable for small embedded systems with limited RAM and ROM.

It includes optional on-the-fly key schedule calculation, for minimal RAM usage if required in a very RAM-constrained application. For systems with sufficient RAM, there is also encryption and decryption with a pre-calculated key schedule.

Normally the S-box implementation is by a simple 256-byte table look-up. An optional smaller S-box implementation is included for a *very* ROM-constrained application, where a 256-byte look-up table might be too big. This would only be expected to be necessary for especially tiny target applications, e.g. an automotive keyless entry remote.

Testing
-------

This has had minimal testing, by inspection of encryption/decryption of one of the [test vectors][3].

License
-------

This code is released under the MIT license. See LICENSE.txt for details.


[1]: http://www.larc.usp.br/~pbarreto/KhazadPage.html
[2]: http://en.wikipedia.org/wiki/KHAZAD
[3]: http://www.larc.usp.br/~pbarreto/khazad-tweak-test-vectors.zip
