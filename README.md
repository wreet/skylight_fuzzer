# skylight_fuzzer
a simple frida-based fuzzer for skylight(WindowServer) based on @ret2systems pwn2own work https://blog.ret2.io/2018/07/25/pwn2own-2018-safari-sandbox/

A reproduction of ret2's skylight fuzzer for MacOS Mojave.

To use it, just run `sudo node driver.js`

You can generate window traffic to be fuzzed however you wish, however I have included a file `wintraffic.js` to get you started. 

more info here: https://wreet.xyz/2019/05/19/reproducing-ret2io-skylight-fuzzer/
