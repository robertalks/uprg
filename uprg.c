#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <libudev.h>

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
static const char *comment = "\nNOTE: Using the persistent rule generator might mean you will need to do extra work to ensure\n"
                             "that it will work accordingly. This means, regenerating the initramfs/initrd image and/or using\n"
                             "'net.ifnames=0' option at boot time.\n"
                             "In openSUSE/SUSE, the user will need to regenerate the initramfs/initrd image, but usually there\n"
                             "is no need for 'net.ifnames=0' option if the persistent rule is available in initramfs/initrd image.";

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

static char *device_syspath(const char *interface)
{
	char *path = NULL;
 
	if (interface) { 
		path = malloc(strlen(syspath) + strlen(interface) + 2);
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
	sprintf(devpath, "%s%s", sysfs, attr);

	return devpath;
}

static char *device_interface(struct udev_device *dev)
{
	const char *attr;
	char *interface = NULL;
  
	attr = udev_device_get_sysname(dev);
	if (attr) {
		interface = malloc(strlen(attr) + 1);
		sprintf(interface, "%s", attr);
	}

	return interface;
}

static int device_type(struct udev_device *dev)
{
	const char *attr;
	int type;

	attr = udev_device_get_sysattr_value(dev, "type");
	if (!attr)
		return -1;
  
	return type = strtol(attr, NULL, 10);
}

static char *device_devtype(struct udev_device *dev)
{
	const char *attr;
	char *devtype;
  
	attr = udev_device_get_devtype(dev);
	devtype = malloc(6);
	if (attr) {
		if (strncmp(attr, "wlan", 4) == 0)
			sprintf(devtype, "wlan");
		if (strncmp(attr, "wwan", 4) == 0)
			sprintf(devtype, "wwan");
	} else
		sprintf(devtype, "eth");

	return devtype;
}

static char *device_macaddr(struct udev_device *dev)
{
	const char *attr;
	char *macaddr = NULL;

	attr = udev_device_get_sysattr_value(dev, "address");
	macaddr = malloc(strlen(attr) + 1);
	sprintf(macaddr, "%s", attr);

	return macaddr;
}

static char *device_pci(struct udev_device *dev)
{
	struct udev_device *dev_parent;
	const char *attr;
	char *pci = NULL;
  
	dev_parent = udev_device_get_parent(dev);
	attr = udev_device_get_sysname(dev_parent);
	pci = malloc(strlen(attr) + 1);
	sprintf(pci, "%s", attr);
  
	return pci;
}

static char *device_driver(struct udev_device *dev)
{
	struct udev_device *dev_parent;
	const char *attr;
	char *driver = NULL;

	dev_parent = udev_device_get_parent(dev);
	attr = udev_device_get_driver(dev_parent);
	driver = malloc(strlen(attr) + 1);
	sprintf(driver, "%s", attr);

	return driver;
}

static char *device_dev_id(struct udev_device *dev)
{
	const char *attr;
	char *dev_id = NULL;

	attr = udev_device_get_sysattr_value(dev, "dev_id");
	dev_id = malloc(strlen(attr) + 1);
	sprintf(dev_id, "%s", attr);

	return dev_id;
}

static char *device_pci_id(struct udev_device *dev)
{
	FILE *f;
	char line[256], path[1024];
	char *interface, *buf;
	char *pci_id = NULL;

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

		if (strncmp(line, "PCI_ID=", 7) == 0)
			pci_id = strdup(&line[7]);
	}
	fclose(f);

	if (!pci_id) {
		pci_id = malloc(6);
		sprintf(pci_id, "0x:0x");
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
		subsystem = malloc(strlen(attr) + 1);
		sprintf(subsystem, "%s", attr);
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
		parent_subsystem = malloc(strlen(attr) + 1);
		sprintf(parent_subsystem, "%s", attr);
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
		fprintf(stderr, "%s: error: cannot create udev context.\n", program);
		exit(1);
	}


	enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "net");
	udev_enumerate_scan_devices(enumerate);
	devices = udev_enumerate_get_list_entry(enumerate);

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path;
		char *i = NULL, *m = NULL, *p = NULL, *d = NULL;
		int t;

		path = udev_list_entry_get_name(dev_list_entry);
		dev = udev_device_new_from_syspath(udev, path);

		if (!dev)
			continue;

		t = device_type(dev);
		if (t != 1)
			continue;

		i = device_interface(dev);
		if (!physical_device(i))
			continue;

		m = device_macaddr(dev);
		p = device_pci(dev);
		d = device_devpath(dev);

		if (i && m && p && d)
			printf("I: INTERFACE: %s\nI: MACADDR: %s\nI: PCI: %s\nI: DEVPATH: %s\n", i, m, p, d);

		free(i);
		free(m);
		free(p);
		free(d);
		udev_device_unref(dev);
	}

	udev_enumerate_unref(enumerate);
	udev_unref(udev);
}

static int device_fillup(char *interface, char *interface_new, struct device_info *data, struct udev_device *dev)
{
	int t;

	t = device_type(dev);
	if (data) {
		data->interface = strdup(interface);
		data->interface_new = strdup(interface_new);
		data->devpath = device_devpath(dev);
		data->syspath = device_syspath(interface);
		data->pci = device_pci(dev);
		data->pci_id = device_pci_id(dev);
		data->macaddr = device_macaddr(dev);
		data->type = t;
		data->dev_id = device_dev_id(dev);
		data->devtype = device_devtype(dev);
		data->subsystem = device_subsystem(dev);
		data->parent_subsystem = device_parent_subsystem(dev);
		data->driver = device_driver(dev);
	} else
		return 1; 
  
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

static void write_rule_stdout(struct device_info *data, int rule_type)
{
	if (rule_type == 0)
		printf("SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                       "ATTR{address}==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                       "KERNEL==\"%s*\", NAME=\"%s\"\n", 
                       data->subsystem, data->macaddr, data->dev_id, data->type, data->devtype, data->interface_new);
	if (rule_type == 1)
		printf("SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                       "KERNELS==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                       "KERNEL==\"%s*\", NAME=\"%s\"\n", 
                       data->subsystem, data->pci, data->dev_id, data->type, data->devtype, data->interface_new);
}

static const char *write_comment(struct device_info *data)
{
	char *buf = NULL;
	char device_type[20];
	const char *comm;
	int len;

	if (strcmp(data->parent_subsystem, "pci") == 0)
		sprintf(device_type, "PCI");
	else if (strcmp(data->parent_subsystem, "usb") == 0)
		sprintf(device_type, "USB");
	else
		sprintf(device_type, "Unknown");

	len = strlen(device_type) + strlen(data->pci_id) + strlen(data->driver);
	buf = malloc(len + 14);
	sprintf(buf, "# %s device %s (%s)", device_type, data->pci_id, data->driver);

	comm = strdup(buf);
	free(buf);

	return comm;
}

static int write_rule(struct device_info *data, char *filename, int rule_type)
{
	FILE *f;

	if (data && filename) {
		f = fopen(filename, "a");
		if (f == NULL)
			return 1;
		const char *comm = write_comment(data);
		fprintf(f, "%s\n", comm);
                if (rule_type == 0) {
			write_rule_stdout(data, rule_type);
			fprintf(f, "SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                                   "ATTR{address}==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                                   "KERNEL==\"%s*\", NAME=\"%s\"\n",
                                   data->subsystem, data->macaddr, data->dev_id, data->type, data->devtype, data->interface_new);
		} else if (rule_type == 1) {
			write_rule_stdout(data, rule_type);
			fprintf(f, "SUBSYSTEM==\"%s\", ACTION==\"add\", DRIVERS==\"?*\", "
                                   "KERNELS==\"%s\", ATTR{dev_id}==\"%s\", ATTR{type}==\"%d\", "
                                   "KERNEL==\"%s*\", NAME=\"%s\"\n",
                                   data->subsystem, data->pci, data->dev_id, data->type, data->devtype, data->interface_new);
		} else
			return 1;

		fclose(f);
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
					fprintf(stderr, "%s: error: current interface already specified.\n", program);
					r = 1;
					goto exit;
				}
				interface = optarg;
				break;
			}
			case 'n': {
				if (interface_new) {
					fprintf(stderr, "%s: error: new interface already specified.\n", program);
					r = 1;
					goto exit;
				}	
				interface_new = optarg;
				break;
			}
			case 'o': {
				if (output_file) {
					fprintf(stderr, "%s: error: output file already specified.\n", program);
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
		fprintf(stderr, "%s: error: missing or invalid options.\n", program);
		r = 1;
		goto exit;
	}

	if (use_mac && use_pci) {
		fprintf(stderr, "%s: error: you cant use both '-m' and '-p' options.\n", program);
		r = 1;
		goto exit;
	}

	if (!use_mac && !use_pci)
		use_mac = true;

	if (!interface && !interface_new) {
		fprintf(stderr, "%s: error: missing or empty interfaces.\n", program);
		r = 1;
		goto exit;
	}

	if (strlen(interface) == 0 || strlen(interface_new) == 0) {
		fprintf(stderr, "%s: error: missing or empty interfaces.\n", program);
		r = 1;
		goto exit;
	}

	if (strcmp(interface_new, "lo") == 0) {
		fprintf(stderr, "%s: error: 'lo' interface is taken and not usable.\n", program);
		r = 1;
		goto exit;
	}

	if (strcmp(interface, interface_new) == 0)
		fprintf(stderr, "%s: warn: you are trying to rename your interface to the same name.\n", program);

	path = device_syspath(interface);
	if (path) {
		if (lstat(path, &stats) != 0) {
			fprintf(stderr, "%s: error: '%s' is not a invalid.\n", program, interface);
			free(path);
			r = 1;
			goto exit;
		}
	}

	if (!physical_device(interface)) {
		fprintf(stderr, "%s: error: interface '%s' is not a physical device.\n", program, interface);
		r = 1; 
		goto exit;
	}

	udev = udev_new();
	if (!udev) {
		fprintf(stderr, "%s: error: cannot create udev context.\n", program);
		r = 1;
		goto exit;
	}

	dev = udev_device_new_from_syspath(udev, path);
	if (!dev) {
		fprintf(stderr, "%s: error: unable to initialize device from udev.\n", program);
		r = 1;
		goto exit_udev;
	}

	if (device_type(dev) != 1) {
		fprintf(stderr, "%s: error: interface '%s' is not a supported device type.\n", program, interface);
		r = 1;
		goto exit_udev;
	}

	data = calloc(1, sizeof(struct device_info));
	if (!data) {
		fprintf(stderr, "%s: error: unable to allocate memory.\n", program);
		r = 1;
		goto exit_udev;
	}

	r = device_fillup(interface, interface_new, data, dev);
	if (r > 0) {
		fprintf(stderr, "%s: error: unable to fillup device structure.\n", program);
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

	if (output_file && strlen(output_file) != 0) {
		printf("Writting persistent rule to %s\n", output_file);
		if (use_mac)
			r = write_rule(data, output_file, 0);
		if (use_pci)
			r = write_rule(data, output_file, 1);
		if (r > 0) {
			fprintf(stderr, "%s: error: unable to write rule to file %s\n", program, output_file);
			goto exit_data;
		}
		printf("%s\n", comment);
	} else {
		if (use_mac)
			write_rule_stdout(data, 0);
		if (use_pci)
			write_rule_stdout(data, 1);
	}

exit_data:
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
