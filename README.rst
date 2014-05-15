uprg
====

**udev persistent rule generator**

This tool will help anybody to generate a persistent rule for a specified network
device. This is not need it for older distros which do systemd implemented, but those
who do, they usually rely on Predictable Network Interface Names, which means that the
network interfaces will be named based on their physical location on the hardware.
Some people do not like the new way of naming the network device, so uprg has been
born. 

The initial project was written in bash and can be found at: 
`https://github.com/robertalks/udev-generate-peristent-rule <https://github.com/robertalks/udev-generate-peristent-rule>`_.

**Pre-build:**
for building this code, you will need to have libudev development libriaries

openSUSE::

    zypper in libudev-devel

Fedora::

    yum install libudev-devel

Ubuntu/Debian::

    apt-get install libudev-dev

**Build:**
::
    $ make


**Install:**
::
    $ make install DESTDIR=/usr/local


License
-------

Copyright 2014 Robert Milasan <rmilasan@suse.com>.

uprg is free software made available under the GPL2. For details see
the LICENSE file.

