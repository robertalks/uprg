uprg
====

**udev persistent rule generator**

This tool will help to generate a persistent rule for a specified network interface.
This is not need it for older distros which do not implement systemd.

The current implementation in systemd is called `Predictable Network Interface Names <http://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/>`_
and it will rename the network interfaces based on their physical location on the hardware,
making the network interface names a bit weird:

New:
enp0s3
wlx0024d7e31130

Old:
eth0
wlan0


The initial project was written in bash and can be found at: 
`https://github.com/robertalks/udev-generate-peristent-rule <https://github.com/robertalks/udev-generate-peristent-rule>`_.

**Requirements:**
for building this code, you will need to have libudev development libriaries, gcc and make.

openSUSE::

    zypper in libudev-devel gcc make

Fedora::

    yum install libudev-devel gcc make

Ubuntu/Debian::

    apt-get install libudev-dev gcc make


**Instructions:**
::
    $ git clone https://github.com/robertalks/uprg.git
    $ cd uprg
    $ make
    $ make install DESTDIR=/usr/local
   

**Usage:**

generate a rule and be verbose, write the output to stdout::

    $ uprg -v -c eth0 -n net0

generate a rule and write it to /etc/udev/rules.d/70-myinterface.rules::

    $ uprg -c enp0s3 -n lan0 -o /etc/udev/rules.d/70-myinterface.rules

list all interfaces which can be renamed::

    $ uprg -l


License
-------

Copyright (C) 2014 Robert Milasan <rmilasan@suse.com>.

uprg is free software made available under the GPL2. For details see
the LICENSE file.

