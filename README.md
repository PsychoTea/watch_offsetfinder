## watch_offsetfinder

A modified version of tihmstar's [offsetfinder](https://github.com/timstar/offsetfinder) for finding v0rtex Apple  Watch offsets.

```Usage: offsetfinder <path to kernelcache>```

OTA files (which include kernelcache's) can be pulled from https://ipsw.me

Extract the files and grab the kernelcache. Use lzssdec to decompress it:

```lzssdec -o 0x1b5 < kernelcachefile > kernelcache.dec```

(You may also need to use 0x1b4 for some kernelcache's as the offset, I'm not really sure)

Currently finding sizeof_task and iouserclient_ipc is broken, so if someone could try and fix them that would be appreciated.
It doesn't find realhost_special or vtab_get_retain_count, but these should be 0x8 and 0x3 respectively, and are printed manually as so.

Credits to tihmstar for the original offsetfinder.
