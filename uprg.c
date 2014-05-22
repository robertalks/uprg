/*
 * Copyright (C) 2014 Robert Milasan <rmilasan@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <libudev.h>

#define STR_LEN 	16384
#define RULE_BY_MAC	0
#define RULE_BY_PCI	1
#define LEVEL_ERR	0
#define LEVEL_INFO	1

struct device_info {
	char *interface;
	char *interface_new;
	char *devpath;
	char *syspath;
	char *pci;
	char *pci_id;
	char *macaddr;
	int type;
	char *dev_id;
	char *devtype;
	char *subsystem;
	char *parent_subsystem;
	char *driver;
};

static const char *syspath = "/sys/class/net";
static const char *program = "uprg";
static const char *program_long = "udev-persistent-rule-generator";
static const char *version = "0.3";
static const char *comment = "\nNOTE: Using the persistent rule generator might mean you will need to do extra work to ensure that it will work accordingly."
                             "\nThis means, regenerating the initramfs/initrd image and/or using 'net.ifnames=0' option at boot time.";

static const struct option options[] = {
	{ "current",  required_argument, NULL, 'c' },
	{ "new",      required_argument, NULL, 'n' },
	{ "output",   required_argument, NULL, 'o' },
	{ "mac",      no_argument,       NULL, 'm' },
	{ "pci",      no_argument,       NULL, 'p' },
	{ "verbose",  no_argument,       NULL, 'v' },
	{ "version",  no_argument,       NULL, 'V' },
	{ "list",     no_argument,       NULL, 'l' },
	{ "help",     no_argument,       NULL, 'h' },
	{}
};

static void help(void)
{
	printf("Usage: %s [OPTION...]\n"
               " -h,--help                  Show this help\n"
               " -l,--list                  List available interfaces\n"
               " -m,--mac                   Generate the persistent rule based on interface MAC address\n"
               "                            (default option, if nothing is specified)\n"
               " -p,--pci                   Generate the persistent rule based on interface PCI slot\n"
               " -v,--verbose               Be verbose\n"
               " -c,--current=<interface>   Current interface name (ex: --current=eth0)\n"
               " -n,--new=<interface>       New interface name (ex: --new=net0)\n"
               " -o,--output=<file>         Where to write the new generate rule (ex: --output=/etc/udev/rules.d/70-persistent-net.rules)\n"
               "                            (default: /dev/stdout)\n\n"
               "Example:\n"
               "    %s -v -c enp0s4 -n lan0\n"
               " or\n"
               "    %s -m -c enp0s4 -n net0 -o /etc/udev/rules.d/70-persistent-net.rules\n"
               " or\n"
               "    %s -p -c wlp3s0 -n wlan0 -o /etc/udev/rules.d/50-mynet.rules\n\n",program, program, program, program);
}

static void _log(int level, const char *fmt, ...)
{
	va_list ap;
	FILE *output = NULL;

	switch (level) {
		case LEVEL_ERR:
			output = stderr;
			break;
		case LEVEL_INFO:
			output = stdout;
			break;
	}

	if (fmt) {
		va_start(ap, fmt);
		fprintf(output, "%s: ", program);
		vfprintf(output, fmt, ap);
		va_end(ap);
	} else
		fprintf(stderr, "%s: try -h|--help for more information.\n", program);
}

#define err(...) _log(LEVEL_ERR, __VA_ARGS__)
#define info(...) _log(LEVEL_INFO, __VA_ARGS__)

static char *device_syspath(const char *interface)
{
	char *path = NULL;

	if (interface) { 
		path = malloc(strlen(syspath) + strlen(interface) + 2);
		if (!path)
			return NULL;
		sprintf(path, "%s/%s", syspath, interface);
	}

	return path;
}

static char *device_devpath(struct udev_device *dev)
{
	char *devpath = NULL;
	const char *sysfs = "/sys";
	const char *attr;
  
	attr = udev_device_get_devpath(dev);
	devpath = malloc(strlen(sysfs) + strlen(attr) + 1);
	if (!devpath)
		return NULL;

	sprintf(devpath, "%s%s", sysfs, attr);

	return devpath;
}

static char *device_interface(struct udev_device *dev)
{
	const char *attr;
	char *interface = NULL;
  
	attr = udev_device_get_sysname(dev);

	if (attr) {
		interface = strdup(attr);
	}

	return interface;
}

static int device_type(struct udev_device *dev)
{
	const char *attr;

	attr = udev_device_get_sysattr_value(dev, "type");
	if (!attr)
		return -1;
  
	return atoi(attr);
}

static char *device_devtype(struct udev_device *dev)
{
	const char *attr;
	char *devtype;
	size_t size = 5;
  
	devtype = malloc(size);
	if (!devtype)
		return NULL;

	attr = udev_device_get_devtype(dev);
	if (attr) {
		if (strncmp(attr, "wlan", 4) == 0)
			snprintf(devtype, size, "wlan");
		if (strncmp(attr, "wwan", 4) == 0)
			snprintf(devtype, size, "wwan");
	} else
		snprintf(devtype, size, "eth");

	return devtype;
}

static char *device_macaddr(struct udev_device *dev)
{
	const char *attr;
	char *macaddr = NULL;

	attr = udev_device_get_sysattr_value(dev, "address");

	if (attr)
		macaddr = strdup(attr);

	return macaddr;
}

static char *device_pci(struct udev_device *dev)
{
	struct udev_device *dev_parent;
	const char *attr;
	char *pci = NULL;
  
	dev_parent = udev_device_get_parent(dev);
	attr = udev_device_get_sysname(dev_parent);

	if (attr)
		pci = strdup(attr);
  
	return pci;
}

static char *device_driver(struct udev_device *dev)
{
	struct udev_device *dev_parent;
	const char *attr;
	char *driver = NULL;

	dev_parent = udev_device_get_parent(dev);
	attr = udev_device_get_driver(dev_parent);

	if (attr)
		driver = strdup(attr);

	return driver;
}

static char *device_dev_id(struct udev_device *dev)
{
	const char *attr;
	char *dev_id = NULL;

	attr = udev_device_get_sysattr_value(dev, "dev_id");

	if (attr)
		dev_id = strdup(attr);

	return dev_id;
}

static char *device_pci_id(struct udev_device *dev)
{
	FILE *f;
	char line[256], path[1024];
	char *interface, *buf;
	char *pci_id = NULL;
	size_t size = 6;

	interface = device_interface(dev);
	buf = device_syspath(interface);
	sprintf(path, "%s/device/uevent", buf);

	f = fopen(path, "re");
	if (f == NULL)
		goto exit;

	while (fgets(line, sizeof(line), f)) {
		char *pos;

		pos = strchr(line, '\n');
		if (pos == NULL)
			continue;
		pos[0] = '\0';

		if (strncmp(line, "PCI_ID=", 7) == 0) {
			pci_id = strdup(&line[7]);
			break;
		}
	}
	fclose(f);

	if (!pci_id) {
		pci_id = malloc(size);
		snprintf(pci_id, size, "0x:0x");
	}

exit:
	free(interface);
	free(buf);

	return pci_id;
}

static char *device_subsystem(struct udev_device *dev)
{
	const char *attr;
	char *subsystem = NULL;

	attr = udev_device_get_subsystem(dev);

	if (attr) {
		subsystem = strdup(attr);
	}

	return subsystem;
}

static char *device_parent_subsystem(struct udev_device *dev)
{
	struct udev_device *dev_parent;
	const char *attr;
	char *parent_subsystem = NULL;

	dev_parent = udev_device_get_parent(dev);
	attr = udev_device_get_subsystem(dev_parent);

	if (attr) {
		parent_subsystem = strdup(attr);
	}

	return parent_subsystem;
}

static bool physical_device(char *interface)
{
	char *path = NULL, *buf = NULL;
	struct stat stats;
	bool physical = false;

	buf = device_syspath(interface);
	if (buf) {
		path = malloc(strlen(buf) + 8);
		sprintf(path, "%s/device", buf);
		if (lstat(path, &stats) == 0)
			physical = true;
	 }

	free(buf);
	free(path);

	return physical;
}

static void list_devices(void)
{
	struct udev *udev;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *devices, *dev_list_entry;
	struct udev_device *dev = NULL;

	udev = udev_new();
	if (!udev) {
		err("cannot create udev context.\n");
		exit(1);
	}

	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	if (!devices) {
		err("unable enumerate udev devices.\n");
		exit(1);
	}

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		char *i = NULL, *m = NULL, *p = NULL, *d = NULL;
		int t;

		path = udev_list_entry_get_name(dev_list_entry);
		dev = udev_device_new_from_syspath(udev, path);

		if (!dev)
			continue;

		t = device_type(dev);
		if (t != 1) {
			udev_device_unref(dev);
			continue;
		}

		i = device_interface(dev);
		if (!physical_device(i)) {
			udev_device_unref(dev);
			free(i);
			continue;
		}

		m = device_macaddr(dev);
		p = device_pci(dev);
		d = device_devpath(dev);

		if (i && m && p && d) {
			printf("I: INTERFACE: %s\nI: MACADDR: %s\nI: PCI: %s\nI: DEVPATH: %s\n", i, m, p, d);
			free(i);
			free(m);
			free(p);
			free(d);
		}

		udev_device_unref(dev);
	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);
}

static int device_fillup(char *interface, char *interface_new, struct device_info *data, struct udev_device *dev)
{
	if (!data)
		return 1;

	data->interface = strdup(interface);
	data->interface_new = strdup(interface_new);
	data->devpath = device_devpath(dev);
	data->syspath = device_syspath(interface);
	data->pci = device_pci(dev);
	data->pci_id = device_pci_id(dev);
	data->macaddr = device_macaddr(dev);
	data->type = device_type(dev);
	data->dev_id = device_dev_id(dev);
	data->devtype = device_devtype(dev);
	data->subsystem = device_subsystem(dev);
	data->parent_subsystem = device_parent_subsystem(dev);
	data->driver = device_driver(dev);
  
	return 0;
}

static struct device_info *device_unref(struct device_info *data)
{
	if (data == NULL)
		return NULL;

	free(data->interface);
	free(data->interface_new);
	free(data->devpath);
	free(data->syspath);
	free(data->pci);
	free(data->pci_id);
	free(data->macaddr);
	free(data->dev_id);
	free(data->devtype);
	free(data->subsystem);
	free(data->parent_subsystem);
	free(data->driver);
	free(data);

	return NULL;
}

static int rule_exists(char *interface, char *filename)
{
	FILE *f;
	char line[STR_LEN];
	int r = 0;

	f = fopen(filename, "re");
	if (f == NULL) {
		r = 1;
		return r;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *pos, *buf = NULL;
		size_t len;

		pos = line;
		while (isspace(pos[0]))
			pos++;

		if (pos[0] == '#')
			continue;

		len = strlen(line);
		if (len < 3)
			continue;

		buf = strstr(line, interface);
		if (buf) {
			r = 2;
			break;
		}
	}
	fclose(f);

	return r;
}

static char *write_comment(struct device_info *data)
{
	char *buf = NULL;
	char device_type[8];
	size_t len;

	if (strcmp(data->parent_subsystem, "pci") == 0)
		snprintf(device_type, sizeof(device_type), "PCI");
	else if (strcmp(data->parent_subsystem, "usb") == 0)
		snprintf(device_type, sizeof(device_type), "USB");
	else
		snprintf(device_type, sizeof(device_type), "Unknown");

	len = strlen(device_type) + strlen(data->pci_id) + strlen(data->driver);
	buf = malloc(len + 14);
	if (!buf)
		return NULL;

	sprintf(buf, "# %s device %s (%s)", device_type, data->pci_id, data->driver);

	return buf;
}

static void write_rule(FILE *file, struct device_info *data, int rule_type)
{
	switch (rule_type) {
			case RULE_BY_MAC:
				fprintf(file, "SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                                       "ATTR{address}==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                                       "KERNEL==\"%s*\", NAME=\"%s\"\n",
                                       data->subsystem, data->macaddr, data->dev_id, data->type, data->devtype, data->interface_new);
				break;
			case RULE_BY_PCI:
				fprintf(file, "SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                                       "KERNELS==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                                       "KERNEL==\"%s*\", NAME=\"%s\"\n",
                                       data->subsystem, data->pci, data->dev_id, data->type, data->devtype, data->interface_new);
				break;
	}
}

static int write_rule_file(struct device_info *data, char *filename, int rule_type)
{
	FILE *file;
	char *comm = NULL;

	if (data && filename) {
		file = fopen(filename, "a");
		if (file == NULL)
			return 1;

		comm = write_comment(data);
		if (comm) {
			fprintf(file, "%s\n", comm);
			free(comm);
		}

		write_rule(file, data, rule_type);

		if (file)
			fclose(file);

	} else
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
	int r = 0;
	struct udev *udev;
	struct udev_device *dev = NULL;
	struct device_info *data = NULL;
	struct stat stats;
	bool use_mac = false, use_pci = false, verbose = false;
	char *interface = NULL, *interface_new = NULL, *output_file = NULL, *path = NULL;

	while(1) {
		int option;

		option = getopt_long(argc, argv, "lmpc:n:o:vVh", options, NULL);
		if (option == -1)
			break;

		switch (option) {
			case 'l':
				list_devices();
				goto exit;
			case 'm':
				use_mac = true;
				break;
			case 'p':
				use_pci = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 'c': {
				if (interface) {
					err("current interface already specified.\n");
					r = 1;
					goto exit;
				}
				interface = optarg;
				break;
			}
			case 'n': {
				if (interface_new) {
					err("new interface already specified.\n");
					r = 1;
					goto exit;
				}	
				interface_new = optarg;
				break;
			}
			case 'o': {
				if (output_file) {
					err("output file already specified.\n");
					r = 1;
					goto exit;
				}
				output_file = optarg;
				break;
			}
			case 'V':
				printf("%s (%s) %s\n", program, program_long, version);
				goto exit;
			case 'h':
				help();
				goto exit;
			default:
				r = 1;
				goto exit;
		}
	}

	if (argc <= 1) {
		help();
		err("missing or invalid options.\n");
		r = 1;
		goto exit;
	}

	if (use_mac && use_pci) {
		err("you cant use both '-m' and '-p' options.\n");
		r = 1;
		goto exit;
	}

	if (!use_mac && !use_pci)
		use_mac = true;

	if (interface == NULL || strlen(interface) <= 0) {
		err("current interface not specified.\n");
		r = 1;
		goto exit;
	}

	if (interface_new == NULL || strlen(interface_new) <= 2) {
		err("new interface not specified or name too small.\n");
		r = 1;
		goto exit;
	}

	if (strcmp(interface_new, "lo") == 0) {
		err("'lo' interface is taken and not usable.\n");
		r = 1;
		goto exit;
	}

	if (strcmp(interface, interface_new) == 0)
		info("you are trying to rename your interface to the same name.\n");

	path = device_syspath(interface);
	if (path) {
		if (lstat(path, &stats) != 0) {
			err("'%s' is not a valid interface.\n", interface);
			free(path);
			r = 1;
			goto exit;
		}
	} else {
		err("interface 'path' is NULL.\n");
		r = 1;
		goto exit;
	}

	if (!physical_device(interface)) {
		err("interface '%s' is not a physical device.\n", interface);
		r = 1; 
		goto exit;
	}

	udev = udev_new();
	if (!udev) {
		err("cannot create udev context.\n");
		r = 1;
		goto exit;
	}

	dev = udev_device_new_from_syspath(udev, path);
	if (!dev) {
		err("unable to initialize device from udev.\n");
		r = 1;
		goto exit_udev;
	}

	if (device_type(dev) != 1) {
		err("interface '%s' is not a supported device type.\n", interface);
		r = 1;
		goto exit_udev;
	}

	data = calloc(1, sizeof(struct device_info));
	if (!data) {
		err("unable to allocate memory.\n");
		r = 1;
		goto exit_udev;
	}

	r = device_fillup(interface, interface_new, data, dev);
	if (r > 0) {
		err("unable to fillup device structure.\n");
		goto exit_data;
	}

	if (verbose)
		printf("I: INTERFACE=%s\n"
                       "I: INTERFACE_NEW=%s\n"
                       "I: MACADDR=%s\n"
                       "I: DEVPATH=%s\n"
                       "I: SYSPATH=%s\n"
                       "I: DEV_ID=%s\n"
                       "I: TYPE=%d\n"
                       "I: SUBSYSTEM=%s\n"
                       "I: PARENT_SUBSYSTEM=%s\n"
                       "I: PCI_ID=%s\n"
                       "I: DRIVER=%s\n",
                       data->interface, data->interface_new, data->macaddr, data->devpath, 
                       data->syspath, data->dev_id, data->type, data->subsystem, data->parent_subsystem,
                       data->pci_id, data->driver);

	if (output_file != NULL && strlen(output_file) > 1) {

		r = rule_exists(data->interface_new, output_file);
		if (r == 2) {
				err("'%s' interface name already in use.\n", data->interface_new);
				goto exit_data;
		}

		printf("Writing generated persistent rule to '%s'.\n", output_file);
		r = write_rule_file(data, output_file, use_mac == true ? RULE_BY_MAC : RULE_BY_PCI);
		if (r > 0) {
			err("unable to write rule to file '%s'.\n", output_file);
			goto exit_data;
		}

		printf("%s\n", comment);
	} else
		write_rule(stdout, data, use_mac == true ? RULE_BY_MAC : RULE_BY_PCI);

exit_data:
	if (path)
		free(path);
	if (data)
		device_unref(data);

exit_udev:
	if (dev)
		udev_device_unref(dev);
	if (udev)
		udev_unref(udev);

exit:
	return r;
}
