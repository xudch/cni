package etcd

import (
    "fmt"
    "net"
    "time"
    "strings"
    "path/filepath"
    "golang.org/x/net/context"
    "github.com/coreos/etcd/client"
)

const last = "last"

type Store struct {
    api client.KeysAPI
    key string
}

func New(Api, network) (*Store, error) {
    path := "/cni/ipam"
    cfg := client.Config{
        Endpoints: []string{Api},
        Transport: client.DefaultTransport,
        HeaderTimeoutPerRequest: time.Second,
    }
    c, err := client.New(cfg)
    if err != nil {
        return nil, err
    }
    key := filepath.Join(path,network)
    api := client.NewKeysAPI(c)
    return &Store{api, key}, nil
}

func (s *Store) Reserve(id string, ip net.IP) (bool, error) {
    key := filepath.Join(s.key, ip.String())
    _,err := s.api.Get(context.Background(),key,nil)
    if err == nil {
        return false,err
    }
    if _,err := s.api.Set(context.Background(),key,id,nil); err != nil {
        s.api.Delete(context.Background(),key,nil)
        return false, err
    }
    lastKey := filepath.Join(s.key, last)
    if _,err := s.api.Set(context.Background(),lastKey,ip.String(),nil); err != nil {
        s.api.Delete(context.Background(),key,nil)
        s.api.Delete(context.Background(),lastKey,nil)
        return false, err
    }
    return true, nil
}

func (s *Store) LastReservedIP() (net.IP, error) {
    lastKey := filepath.Join(s.key, last)
    lastIp,err := s.api.Get(context.Background(),lastKey,nil)
    if err != nil {
        return nil, fmt.Errorf("Failed to retrieve last reserved ip: %v", err)
    }
    return net.ParseIP(lastIp.Node.Value), nil
}

func (s *Store) Release(ip net.IP) error {
    key := filepath.Join(s.key,ip.String())
    _,err := s.api.Delete(context.Background(),key,nil)
    return err
}

func (s *Store) ReleaseByID(id string) error{
    resp,err := s.api.Get(context.Background(),s.key,nil)
    if err != nil {
        return err
    }
    for i := 0; i < resp.Node.Nodes.Len();i++ {
        keyip := resp.Node.Nodes[i].Key
        splitip := strings.Split(keyip, "/")
        l := len(splitip)
        ip := splitip[l-1]
        if id == resp.Node.Nodes[i].Value {
            key := filepath.Join(s.key,ip)
            _,err = s.api.Delete(context.Background(),key,nil)
            if err != nil {
                return err
            }
        }
    }
    return nil
}
