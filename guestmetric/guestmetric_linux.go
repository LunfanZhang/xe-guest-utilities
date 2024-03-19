package guestmetric

import (
	"bufio"
	"bytes"
	"fmt"
	xenstoreclient "github.com/xenserver/xe-guest-utilities/xenstoreclient"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"net"
)

type Collector struct {
	Client xenstoreclient.XenStoreClient
	Ballon bool
	Debug  bool
}

func (c *Collector) CollectOS() (GuestMetric, error) {
	current := make(GuestMetric, 0)
	f, err := os.OpenFile("/var/cache/xe-linux-distribution", os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(strings.Trim(strings.TrimSpace(parts[1]), "\""))
			current[k] = v
		}
	}
	return prefixKeys("data/", current), nil
}

func (c *Collector) CollectMisc() (GuestMetric, error) {
	current := make(GuestMetric, 0)
	if c.Ballon {
		current["control/feature-balloon"] = "1"
	} else {
		current["control/feature-balloon"] = "0"
	}
	current["attr/PVAddons/Installed"] = "1"
	current["attr/PVAddons/MajorVersion"] = "@PRODUCT_MAJOR_VERSION@"
	current["attr/PVAddons/MinorVersion"] = "@PRODUCT_MINOR_VERSION@"
	current["attr/PVAddons/MicroVersion"] = "@PRODUCT_MICRO_VERSION@"
	current["attr/PVAddons/BuildVersion"] = "@NUMERIC_BUILD_NUMBER@"

	return current, nil
}

func (c *Collector) CollectMemory() (GuestMetric, error) {
	current := make(GuestMetric, 0)
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	foundMemAvailabel := false
	for scanner.Scan() {
		parts := regexp.MustCompile(`\w+`).FindAllString(scanner.Text(), -1)
		switch parts[0] {
		case "MemTotal":
			current["meminfo_total"] = parts[1]
		case "MemFree":
			if !foundMemAvailabel{
				current["meminfo_free"] = parts[1]
			} 
		case "MemAvailable":
			foundMemAvailabel = true
			current["meminfo_free"] = parts[1]
		}
	}
	return prefixKeys("data/", current), nil
}

func enumNetworkAddresses(iface string) (GuestMetric, error) {
	const (
		IP_RE   string = `(\d{1,3}\.){3}\d{1,3}`
		IPV6_RE string = `[\da-f:]+[\da-f]`
	)

	var (
		IP_IPV4_ADDR_RE       = regexp.MustCompile(`inet\s*(` + IP_RE + `).*\se[a-zA-Z0-9]+[\s\n]`)
		IP_IPV6_ADDR_RE       = regexp.MustCompile(`inet6\s*(` + IPV6_RE + `)`)
		IFCONFIG_IPV4_ADDR_RE = regexp.MustCompile(`inet addr:\s*(` + IP_RE + `)`)
		IFCONFIG_IPV6_ADDR_RE = regexp.MustCompile(`inet6 addr:\s*(` + IPV6_RE + `)`)
	)

	d := make(GuestMetric, 0)

	var v4re, v6re *regexp.Regexp
	var out string
	var err error
	if out, err = runCmd("ip", "addr", "show", iface); err == nil {
		v4re = IP_IPV4_ADDR_RE
		v6re = IP_IPV6_ADDR_RE
	} else if out, err = runCmd("ifconfig", iface); err == nil {
		v4re = IFCONFIG_IPV4_ADDR_RE
		v6re = IFCONFIG_IPV6_ADDR_RE
	} else {
		return nil, fmt.Errorf("Cannot find ip/ifconfig command")
	}

	m := v4re.FindAllStringSubmatch(out, -1)
	if m != nil {
		for i, parts := range m {
			d[fmt.Sprintf("ipv4/%d", i)] = parts[1]
		}
	}
	m = v6re.FindAllStringSubmatch(out, -1)
	if m != nil {
		for i, parts := range m {
			d[fmt.Sprintf("ipv6/%d", i)] = parts[1]
		}
	}

	return d, nil
}

func getPlainVifId(path string) (string, error) {
	nodenamePath := fmt.Sprintf("%s/device/nodename", path)
	strLine, err := readSysfs(nodenamePath)
	if err != nil {
		return "", err
	}
	vifId := ""
	reNodename := regexp.MustCompile(`^device\/vif\/(\d+)$`)
	if matched := reNodename.FindStringSubmatch(strLine); matched != nil {
		vifId = matched[1]
	}
	if vifId == "" {
		return "", fmt.Errorf("Not found string like \"device/vif/[id]\" in file %s", nodenamePath)
	} else {
		return vifId, nil
	}
}

func (c *Collector) getSriovVifId(path string) (string, error) {
	sriovDevicePath := "xenserver/device/net-sriov-vf"
	macAddress, err := readSysfs(path + "/address")
	if err != nil {
		return "", err
	}
	subPaths, err := c.Client.List(sriovDevicePath)
	if err != nil {
		return "", err
	}
	for _, subPath := range subPaths {
		iterMac, err := c.Client.Read(fmt.Sprintf("%s/%s/mac", sriovDevicePath, subPath))
		if err != nil {
			continue
		}
		if iterMac == macAddress {
			return subPath, nil
		}
	}
	return "", fmt.Errorf("Cannot find a MAC address to map with %s", path)
}

// return vif_xenstore_prefix * vif_id * error where
// `vif_xenstore_prefix` could be either `attr/vif` for plain VIF or
// `xenserver/attr/net-sriov-vf` for SR-IOV VIF
func (c *Collector) getTargetXenstorePath(path string) (string, string, error) {
	plainVifPrefix := "attr/vif"
	sriovVifPrefix := "xenserver/attr/net-sriov-vf"
	// try to get `vif_id` from nodename interface, only a plain VIF have the nodename interface.
	vifId, err1 := getPlainVifId(path)
	if vifId != "" {
		return plainVifPrefix, vifId, nil
	}
	// not a plain VIF, it could possible be an SR-IOV VIF, try to get vif_id from MAC address mapping
	vifId, err2 := c.getSriovVifId(path)
	if vifId != "" {
		return sriovVifPrefix, vifId, nil
	}
	return "", "", fmt.Errorf("Failed to get VIF ID, errors: %s | %s", err1.Error(), err2.Error())
}

func (c *Collector) CollectNetworkAddr() (GuestMetric, error) {
	current := make(GuestMetric, 0)

	var paths []string
	vifNamePrefixList := [...]string{"eth", "eno", "ens", "emp", "enx", "enX"}
	for _, prefix := range vifNamePrefixList {
		prefixPaths, err := filepath.Glob(fmt.Sprintf("/sys/class/net/%s*", prefix))
		if err != nil {
			return nil, err
		}
		paths = append(paths, prefixPaths...)
	}
	for _, path := range paths {
		// a path is going to be like "/sys/class/net/eth0"
		prefix, vifId, err := c.getTargetXenstorePath(path)
		if err != nil {
			continue
		}
		iface := filepath.Base(path)
		if addrs, err := enumNetworkAddresses(iface); err == nil {
			for tag, addr := range addrs {
				current[fmt.Sprintf("%s/%s/%s", prefix, vifId, tag)] = addr
			}
		}
	}
	return current, nil
}

func printAllAttrs(attrs *netlink.LinkAttrs, logger *log.logger){
	logger.Printf("The interface name is %s", attrs.Name)
	logger.Printf("The interface index is %d", attrs.Index)
	logger.Printf("The interface hardware address is %s", attrs.HardwareAddr)
	logger.Printf("The interface flags is %d", attrs.Flags)
	logger.Printf("The interface MTU is %d", attrs.MTU)
	logger.Printf("The interface master index is %d", attrs.MasterIndex)
	logger.Printf("The interface parent index is %d", attrs.ParentIndex)
	logger.Printf("The interface alias is %s", attrs.Alias)
	logger.Printf("The interface statistics is %v", attrs.Statistics)
	for vf := range attrs.Vfs {
		logger.Printf("The interface vf id is %d", vf.ID)
		logger.Printf("The interface vf mac address is %s", vf.Mac)
		logger.Printf("The interface vf vlan id is %d", vf.Vlan)
		logger.Printf("The interface vf qos is %d", vf.Qos)
		logger.Printf("The interface vf tx rate is %d", vf.TxRate)
	}
	logger.Printf("The interface promisc is %t", attrs.Promisc)
	logger.Printf("The interface Protinfo is %v", attrs.Protinfo)
	logger.Printf("The interface operstate is %s", attrs.OperState)
}

func handleNewLinkEvent(collector *guestmetric.Collector, attrs *netlink.LinkAttrs, logger *log.logger) {
    printAllAttrs(attrs, logger)
    paths, err := filepath.Glob(fmt.Sprintf("/sys/class/net/%s*", attrs.Name))
    if err != nil {
        logger.Printf("Failed to get the path of the network interface %s, error: %s", attrs.Name, err)
        return
    }
    if len(paths) == 0 {
        logger.Printf("No paths matched the pattern for the network interface %s", attrs.Name)
        return
    }
    path := paths[0]
    iface := filepath.Base(path)
    logger.Printf("The vif id is %d", attrs.Vfs[0].ID)
    prefix, vifId, err := collector.getTargetXenstorePath(iface)
    if err != nil {
        logger.Printf("Failed to get target xenstore path for interface %s, error: %s", iface, err)
        return
    }
    if addrs, err := enumNetworkAddresses(iface); err == nil {
        for tag, addr := range addrs {
            err := collector.Client.Write(fmt.Sprintf("%s/%s/%s", prefix, vifId, tag), addr)
            if err != nil {
                logger.Printf("Failed to write the address %s to xenstore, error: %s", addr, err)
            }
        }
    } else {
        logger.Printf("Failed to enumerate network addresses for interface %s, error: %s", iface, err)
    }
}

func handleDelLinkEvent(collector *guestmetric.Collector, attrs *netlink.LinkAttrs, logger *log.logger) {
	printAllAttrs(attrs, logger)
	vfID := attrs.Vfs[0].ID
	logger.Printf("The vif id is %d", vfID)
	paths := []string{
		fmt.Sprintf("attr/vif/%s", vfID),
		fmt.Sprintf("xenserver/attr/net-sriov-vf/%s", vfID),
	}

	for _, path := range paths {
		if _, err := collector.Client.Read(path); err != nil {
			logger.Printf("Failed to read the path %s from xenstore, error: %s", path, err)
		}
		if err := collector.Client.Rm(path); err != nil {
			logger.Printf("Failed to remove the path %s from xenstore, error: %s", path, err)
		}
	}
}


func handleNewAddrEvent(collector *guestmetric.Collector, attrs *netlink.LinkAttrs, logger *log.logger) {
	printAllAttrs(attrs, logger)
	prefixPaths, err := filepath.Glob(fmt.Sprintf("/sys/class/net/%s*", attrs.Name))
	if err != nil {
		logger.Printf("Failed to get the path of the network interface %s, error: %s", attrs.Name, err)
		return
	}

	prefix, vifID, err := getTargetXenstorePath(collector, prefixPaths)
	if err != nil {
		logger.Printf("Failed to get the target xenstore path, error: %s", err)
		return
	}

	iface, err := net.InterfaceByName(attrs.Name)
	if err != nil {
		logger.Printf("Failed to get the interface by name %s, error: %s", attrs.Name, err)
		return
	}

	addrs, err := iface.Addrs()
	if err != nil {
		logger.Printf("Failed to get the addresses of the interface %s, error: %s", attrs.Name, err)
		return
	}

	for _, addr := range addrs {
		ip := addr.IP
		if ip.To4() != nil {
			err = collector.Client.Write(fmt.Sprintf("%s/%s/%s", prefix, vifID, "ipv4"), ip.String())
		} else if ip.To16() != nil {
			err = collector.Client.Write(fmt.Sprintf("%s/%s/%s", prefix, vifID, "ipv6"), ip.String())
		}
		if err != nil {
			logger.Printf("Failed to write the address %s to xenstore, error: %s", addr, err)
		}
	}
}

func readSysfs(filename string) (string, error) {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0666)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan()
	return scanner.Text(), nil
}

func (c *Collector) CollectDisk() (GuestMetric, error) {
	pi := make(GuestMetric, 0)

	disks := make([]string, 0)
	paths, err := filepath.Glob("/sys/block/*/device")
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		disk := filepath.Base(strings.TrimSuffix(filepath.Dir(path), "/"))
		disks = append(disks, disk)
	}

	var sortedDisks sort.StringSlice = disks
	sortedDisks.Sort()

	part_idx := 0
	for _, disk := range sortedDisks[:] {
		paths, err = filepath.Glob(fmt.Sprintf("/dev/%s?*", disk))
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			p := filepath.Base(path)
			line, err := readSysfs(fmt.Sprintf("/sys/block/%s/%s/size", disk, p))
			if err != nil {
				return nil, err
			}
			size, err := strconv.ParseInt(line, 10, 64)
			if err != nil {
				return nil, err
			}
			blocksize := 512
			if bs, err := readSysfs(fmt.Sprintf("/sys/block/%s/queue/physical_block_size", disk)); err == nil {
				if bs1, err := strconv.Atoi(bs); err == nil {
					blocksize = bs1
				}
			}
			real_dev := ""
			if c.Client != nil {
				nodename, err := readSysfs(fmt.Sprintf("/sys/block/%s/device/nodename", disk))
				if err == nil {
					backend, err := c.Client.Read(fmt.Sprintf("%s/backend", nodename))
					if err != nil {
						return nil, err
					}
					real_dev, err = c.Client.Read(fmt.Sprintf("%s/dev", backend))
					if err != nil {
						return nil, err
					}
				}
			}
			name := path
			blkid, err := runCmd("blkid", "-s", "UUID", path)
			if err != nil {
				// ignore blkid errors
				blkid = ""
			}
			if strings.Contains(blkid, "=") {
				parts := strings.SplitN(strings.TrimSpace(blkid), "=", 2)
				name = fmt.Sprintf("%s(%s)", name, strings.Trim(parts[1], "\""))
			}
			i := map[string]string{
				"extents/0": real_dev,
				"name":      name,
				"size":      strconv.FormatInt(size*int64(blocksize), 10),
			}
			output, err := runCmd("pvs", "--noheadings", "--units", "b", path)
			if err == nil && output != "" {
				parts := regexp.MustCompile(`\s+`).Split(output, -1)[1:]
				i["free"] = strings.TrimSpace(parts[5])[:len(parts[5])-1]
				i["filesystem"] = strings.TrimSpace(parts[2])
				i["mount_points/0"] = "[LVM]"
			} else {
				output, err = runCmd("mount")
				if err == nil {
					m := regexp.MustCompile(`(?m)^(\S+) on (\S+) type (\S+)`).FindAllStringSubmatch(output, -1)
					if m != nil {
						for _, parts := range m {
							if parts[1] == path {
								i["mount_points/0"] = parts[2]
								i["filesystem"] = parts[3]
								break
							}
						}
					}
				}
				output, err = runCmd("df", path)
				if err == nil {
					scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
					scanner.Scan()
					scanner.Scan()
					parts := regexp.MustCompile(`\s+`).Split(scanner.Text(), -1)
					free, err := strconv.ParseInt(parts[3], 10, 64)
					if err == nil {
						i["free"] = strconv.FormatInt(free*1024, 10)
					}
				}
			}
			for k, v := range i {
				pi[fmt.Sprintf("data/volumes/%d/%s", part_idx, k)] = v
			}
			part_idx += 1
		}
	}
	return pi, nil
}
