// Package snmpclient 提供从 config.SNMPDevice 构造 *gosnmp.GoSNMP 客户端的
// 公共逻辑，被 snmppoll、ifdiscovery、bgpcheck(method=snmp) 三个模块共用，
// 避免 SNMPv3 安全参数拼装代码三处重复。
package snmpclient

import (
	"context"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/Cion-1221/NMS_Agent/internal/config"
)

// New 按设备配置构造一个尚未 Connect 的 *gosnmp.GoSNMP 客户端，调用方负责
// Connect()/Conn.Close()。
func New(ctx context.Context, dev config.SNMPDevice, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	port := dev.Port
	if port == 0 {
		port = 161
	}

	client := &gosnmp.GoSNMP{
		Target:    dev.Address,
		Port:      uint16(port),
		Transport: "udp",
		Timeout:   timeout,
		Retries:   retries,
		Context:   ctx,
	}

	switch dev.Version {
	case "v1":
		client.Version = gosnmp.Version1
		client.Community = dev.Community

	case "v3":
		if dev.V3 == nil {
			return nil, fmt.Errorf("snmp version v3 requires the v3 block to be set")
		}
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = securityLevelFlags(dev.V3.SecurityLevel)
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 dev.V3.Username,
			AuthenticationProtocol:   authProtocol(dev.V3.AuthProtocol),
			AuthenticationPassphrase: dev.V3.AuthKey,
			PrivacyProtocol:          privProtocol(dev.V3.PrivProtocol),
			PrivacyPassphrase:        dev.V3.PrivKey,
		}

	default: // "v2c" 及空值，兼容多数现网设备的默认配置
		client.Version = gosnmp.Version2c
		client.Community = dev.Community
	}

	return client, nil
}

func securityLevelFlags(level string) gosnmp.SnmpV3MsgFlags {
	switch level {
	case "authPriv":
		return gosnmp.AuthPriv
	case "authNoPriv":
		return gosnmp.AuthNoPriv
	default:
		return gosnmp.NoAuthNoPriv
	}
}

func authProtocol(name string) gosnmp.SnmpV3AuthProtocol {
	switch name {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func privProtocol(name string) gosnmp.SnmpV3PrivProtocol {
	switch name {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}
