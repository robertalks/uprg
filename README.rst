uprg
====

**udev persistent rule generator**

This tool will help anybody to generate a persistent rule for a specified network
interface. This is not need it for older distros which do systemd implemented, but those
who do, they usually rely on `Predictable Network Interface Names <http://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/>`_, which means that the
network interfaces will be named based on their physical location on the hardware.
Some people do not like the new way of naming the network interfaces, so uprg has been
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


**Usage:**

generate a rule and be verbose, write the output to stdout::

    $ uprg -v -c eth0 -n net0

generate a rule and write it to /etc/udev/rules.d/70-myinterface.rules::

    $ uprg -c enp0s3 -n lan0 -o /etc/udev/rules.d/70-myinterface.rules

list all interfaces which can be renamed::

    $ uprg -l


License
-------

Copyright 2014 Robert Milasan <rmilasan@suse.com>.

uprg is free software made available under the GPL2. For details see
the LICENSE file.

