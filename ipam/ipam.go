
package main

import (
    "fmt"
    "net"
    "encoding/json"
    "cni/ipam/etcd"
    "github.com/containernetworking/cni/pkg/ip"
    "github.com/containernetworking/cni/pkg/skel"
    "github.com/containernetworking/cni/pkg/types"
    "github.com/containernetworking/cni/pkg/version"
)

func main() {
    skel.PluginMain(cmdAdd, cmdDel, version.Legacy)
}

func cmdAdd(args *skel.CmdArgs) error {
    ipamConf,err := LoadIPAMConfig(args.StdinData, args.Args)
    dnsConf   := ipamConf.Dns
    if err != nil {
        return err
    }

    store, err := etcd.New(ipamConf.Api,ipamConf.Name)
    if err != nil {
        return err
    }

    allocator, err := NewIPAllocator(ipamConf, store)
    if err != nil {
        return err
    }

    ipConf, err := allocator.Get(args.ContainerID)
    if err != nil {
        return err
    }

    r := &types.Result{
        IP4: ipConf,
        DNS: dnsConf,
    }
    return r.Print()
}

func cmdDel(args *skel.CmdArgs) error {
    ipamConf, err := LoadIPAMConfig(args.StdinData, args.Args)
    if err != nil {
        return err
    }

    store, err := etcd.New(ipamConf.Api,ipamConf.Name)
    if err != nil {
        return err
    }

    allocator, err := NewIPAllocator(ipamConf, store)
    if err != nil {
        return err
    }

    return allocator.Release(args.ContainerID)
}
type Store interface {
    Reserve(id string, ip net.IP) (bool, error)
    LastReservedIP() (net.IP, error)
    Release(ip net.IP) error
    ReleaseByID(id string) error
}

type IPAllocator struct {
    start net.IP
    end   net.IP
    conf  *IPAMConfig
    store Store
}

func NewIPAllocator(conf *IPAMConfig, store Store) (*IPAllocator, error) {
    ones, masklen := conf.Subnet.Mask.Size()
    if ones > masklen-2 {
        return nil, fmt.Errorf("Network %v too small to allocate from", conf.Subnet)
    }

    var (
        start net.IP
        end   net.IP
        err   error
    )
    start, end, err = networkRange((*net.IPNet)(&conf.Subnet))
    if err != nil {
        return nil, err
    }

    start = ip.NextIP(start)

    if conf.RangeStart != nil {
        if err := validateRangeIP(conf.RangeStart, (*net.IPNet)(&conf.Subnet), nil, nil); err != nil {
            return nil, err
        }
        start = conf.RangeStart
    }
    if conf.RangeEnd != nil {
        if err := validateRangeIP(conf.RangeEnd, (*net.IPNet)(&conf.Subnet), start, nil); err != nil {
            return nil, err
        }
        end = conf.RangeEnd
    }
    return &IPAllocator{start, end, conf, store}, nil
}

func canonicalizeIP(ip net.IP) (net.IP, error) {
    if ip.To4() != nil {
        return ip.To4(), nil
    } else if ip.To16() != nil {
        return ip.To16(), nil
    }
    return nil, fmt.Errorf("IP %s not v4 nor v6", ip)
}

func validateRangeIP(ip net.IP, ipnet *net.IPNet, start net.IP, end net.IP) error {
    var err error

    ip, err = canonicalizeIP(ip)
    if err != nil {
        return err
    }

    if !ipnet.Contains(ip) {
        return fmt.Errorf("%s not in network: %s", ip, ipnet)
    }

    if start != nil {
        start, err = canonicalizeIP(start)
        if err != nil {
            return err
        }
        if len(ip) != len(start) {
            return fmt.Errorf("%s %d not same size IP address as start %s %d", ip, len(ip), start, len(start))
        }
        for i := 0; i < len(ip); i++ {
            if ip[i] > start[i] {
                break
            } else if ip[i] < start[i] {
                return fmt.Errorf("%s outside of network %s with start %s", ip, ipnet, start)
            }
        }
    }

    if end != nil {
        end, err = canonicalizeIP(end)
        if err != nil {
            return err
        }
        if len(ip) != len(end) {
            return fmt.Errorf("%s %d not same size IP address as end %s %d", ip, len(ip), end, len(end))
        }
        for i := 0; i < len(ip); i++ {
            if ip[i] < end[i] {
                break
            } else if ip[i] > end[i] {
                return fmt.Errorf("%s outside of network %s with end %s", ip, ipnet, end)
            }
        }
    }
    return nil
}

func (a *IPAllocator) Get(id string) (*types.IPConfig, error) {

    gw := a.conf.Gateway
    if gw == nil {
        gw = ip.NextIP(a.conf.Subnet.IP)
    }

    var requestedIP net.IP
    if a.conf.Args != nil {
        requestedIP = a.conf.Args.IP
    }

    if requestedIP != nil {
        if gw != nil && gw.Equal(a.conf.Args.IP) {
            return nil, fmt.Errorf("requested IP must differ gateway IP")
        }

        subnet := net.IPNet{
            IP:   a.conf.Subnet.IP,
            Mask: a.conf.Subnet.Mask,
        }
        err := validateRangeIP(requestedIP, &subnet, a.start, a.end)
        if err != nil {
            return nil, err
        }

        reserved, err := a.store.Reserve(id, requestedIP)
        if err != nil {
            return nil, err
        }

        if reserved {
            return &types.IPConfig{
                IP:      net.IPNet{IP: requestedIP, Mask: a.conf.Subnet.Mask},
                Gateway: gw,
                Routes:  a.conf.Routes,
            }, nil
        }
        return nil, fmt.Errorf("requested IP address %q is not available in network: %s", requestedIP, a.conf.Name)
    }

    startIP, endIP := a.getSearchRange()
    for cur := startIP; ; cur = a.nextIP(cur) {
        if gw != nil && cur.Equal(gw) {
            continue
        }

        reserved, err := a.store.Reserve(id, cur)
        if err != nil {
            return nil, err
        }
        if reserved {
            return &types.IPConfig{
                IP:      net.IPNet{IP: cur, Mask: a.conf.Subnet.Mask},
                Gateway: gw,
                Routes:  a.conf.Routes,
            }, nil
        }
        if cur.Equal(endIP) {
            break
        }
    }
    return nil, fmt.Errorf("no IP addresses available in network: %s", a.conf.Name)
}

func (a *IPAllocator) Release(id string) error {
    return a.store.ReleaseByID(id)
}

func networkRange(ipnet *net.IPNet) (net.IP, net.IP, error) {
    if ipnet.IP == nil {
        return nil, nil, fmt.Errorf("missing field %q in IPAM configuration", "subnet")
    }
    ip, err := canonicalizeIP(ipnet.IP)
    if err != nil {
        return nil, nil, fmt.Errorf("IP not v4 nor v6")
    }

    if len(ip) != len(ipnet.Mask) {
        return nil, nil, fmt.Errorf("IPNet IP and Mask version mismatch")
    }

    var end net.IP
    for i := 0; i < len(ip); i++ {
        end = append(end, ip[i]|^ipnet.Mask[i])
    }

    if ip.To4() != nil {
        end[3]--
    }

    return ipnet.IP, end, nil
}

func (a *IPAllocator) nextIP(curIP net.IP) net.IP {
    if curIP.Equal(a.end) {
        return a.start
    }
    return ip.NextIP(curIP)
}

func (a *IPAllocator) getSearchRange() (net.IP, net.IP) {
    var startIP net.IP
    var endIP net.IP
    startFromLastReservedIP := false
    lastReservedIP, err := a.store.LastReservedIP()
//    if err != nil {
//        log.Printf("Error retriving last reserved ip: %v", err)
//    } else if lastReservedIP != nil {
    if err == nil {
        if lastReservedIP != nil {
            subnet := net.IPNet{
                IP:   a.conf.Subnet.IP,
                Mask: a.conf.Subnet.Mask,
            }
            err := validateRangeIP(lastReservedIP, &subnet, a.start, a.end)
            if err == nil {
                startFromLastReservedIP = true
            }
        }
    }
    if startFromLastReservedIP {
        startIP = a.nextIP(lastReservedIP)
        endIP = lastReservedIP
    } else {
        startIP = a.start
        endIP = a.end
    }
    return startIP, endIP
}

type IPAMConfig struct {
    Name       string
    Dns        types.DNS
    Type       string        `json:"type"`
    Api        string        `json:"api"`
    RangeStart net.IP        `json:"rangeStart"`
    RangeEnd   net.IP        `json:"rangeEnd"`
    Subnet     types.IPNet   `json:"subnet"`
    Gateway    net.IP        `json:"gateway"`
    Routes     []types.Route `json:"routes"`
    Args       *IPAMArgs     `json:"-"`
}

type IPAMArgs struct {
    types.CommonArgs
    IP net.IP `json:"ip,omitempty"`
}

type Net struct {
    Name string      `json:"name"`
    IPAM *IPAMConfig `json:"ipam"`
    Dns  types.DNS   `json:"dns"`
}


//type Dns struct {
//    Nameservers []string `json:"nameservers"`
//    Domain      string   `json:"domain"`
//    Search      []string `json:"search"`
//    Options     []string `json:"options"`
//}

func LoadIPAMConfig(bytes []byte, args string) (*IPAMConfig, error) {
    n := Net{}
    if err := json.Unmarshal(bytes, &n); err != nil {
        return nil, err
    }

    if args != "" {
        n.IPAM.Args = &IPAMArgs{}
        err := types.LoadArgs(args, n.IPAM.Args)
        if err != nil {
            return nil, err
        }
    }

    if n.IPAM == nil {
        return nil,fmt.Errorf("IPAM config missing 'ipam' key")
    }

    n.IPAM.Name = n.Name
    n.IPAM.Dns  = n.Dns

    return n.IPAM,nil
}
