/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package probes

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/connetos/anywatch/common"
	//"github.com/connetos/anywatch/config"
	"github.com/connetos/anywatch/logging"
	"github.com/connetos/anywatch/topology"
	"github.com/connetos/anywatch/topology/graph"
	"github.com/soniah/gosnmp"
)

const (
	OidSysDesc     = ".1.3.6.1.2.1.1.1.0"
	OidSysObjectId = ".1.3.6.1.2.1.1.2.0"
	OidSysUptime   = ".1.3.6.1.2.1.1.3.0"
	OidSysContact  = ".1.3.6.1.2.1.1.4.0"
	OidSysName     = ".1.3.6.1.2.1.1.5.0"
	OidSysLocation = ".1.3.6.1.2.1.1.6.0"
	OidSysServices = ".1.3.6.1.2.1.1.7.0"

	OidBoardSn = "1.3.6.1.2.1.47.1.1.1.1.11.256"

	// interfaces
	OidIfPhyAddr    = ".1.3.6.1.2.1.2.2.1.6"
	OidIfOperStatus = ".1.3.6.1.2.1.2.2.1.8"
	OidIfDescr      = ".1.3.6.1.2.1.2.2.1.2"
	OidIfMTU        = ".1.3.6.1.2.1.2.2.1.4"
	OidIfSpeed      = ".1.3.6.1.2.1.2.2.1.5"
	OidIfAlias      = ".1.3.6.1.2.1.31.1.1.1.18"

	OidIpForwarding = ".1.3.6.1.2.1.4.1.0"

	OidIpAddr    = ".1.3.6.1.2.1.4.20.1.1"
	OidIpIfindex = ".1.3.6.1.2.1.4.20.1.2"
	OidIpMask    = ".1.3.6.1.2.1.4.20.1.3"

	OidRouteDest    = ".1.3.6.1.2.1.4.21.1.1"
	OidRouteIfindex = ".1.3.6.1.2.1.4.21.1.2"
	OidRouteNexthop = ".1.3.6.1.2.1.4.21.1.7"
	OidRouteType    = ".1.3.6.1.2.1.4.21.1.8"
	OidRouteMask    = ".1.3.6.1.2.1.4.21.1.11"

	OidEnterprises = ".1.3.6.1.4.1"

	OidBaseNumPorts = ".1.3.6.1.2.1.17.1.2.0"
	OidStpRootCost  = ".1.3.6.1.2.1.17.2.6.0"
	OidStpRootPort  = ".1.3.6.1.2.1.17.2.7.0"
	OidFdbAddress   = ".1.3.6.1.2.1.17.4.3.1.1"

	// dot1dBase
	OidTpFdbPort              = ".1.3.6.1.2.1.17.4.3.1.2"
	OidPhysAddress            = ".1.3.6.1.2.1.3.1.1.2"
	OidBasePort               = ".1.3.6.1.2.1.17.1.4.1.1"
	OidBasePortIfindex        = ".1.3.6.1.2.1.17.1.4.1.2"
	OidTpFdb2Port             = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	OidDot1dBaseBridgeAddress = ".1.3.6.1.2.1.17.1.1.0"

	// qBridgeMIB
	OidDot1qPvid                     = ".1.3.6.1.2.1.17.7.1.4.5.1.1"
	OidDot1qVlanFdbId                = ".1.3.6.1.2.1.17.7.1.4.2.1.3"
	OidDot1qVlanCurrentEgressPorts   = ".1.3.6.1.2.1.17.7.1.4.2.1.4"
	OidDot1qVlanCurrentUntaggedPorts = ".1.3.6.1.2.1.17.7.1.4.2.1.5"

	OidIpNetToMediaPhysAddress = ".1.3.6.1.2.1.4.22.1.2"

	// LLDP
	OidLldpRemChassisIdSubType = ".1.0.8802.1.1.2.1.4.1.1.4"
	OidLldpRemChassisId        = ".1.0.8802.1.1.2.1.4.1.1.5"
	OidLldpRemPortIdSubType    = ".1.0.8802.1.1.2.1.4.1.1.6"
	OidLldpRemPortId           = ".1.0.8802.1.1.2.1.4.1.1.7"
	OidLldpRemManAddrIfId      = ".1.0.8802.1.1.2.1.4.2.1.4"
	OidLldpLocalManAddrIfId    = ".1.0.8802.1.1.2.1.3.8.1.5"
)

const (
	UnknownType = iota
	ServersType
	SwitchL2SnmpType
	PrinterType
	SwitchL3Type
	RouteType
	DeviceType
	GateDeviceType
	HostType
	SwitchL2Type
	WirelessRouteType
	Subnetype
)

const (
	DirectRouteType   = 3
	InDirectRouteType = 4
)

const (
	TypePortUp = 1 + iota
	TypePortDown
	TypePortLeaf
)

const (
	DetectConfigFile = "etc/topology_detect.json"
)

type snmpConf struct {
	coreIp      string
	port        uint16
	scanLayer   int
	snmpVersion int
	icmpTimeout int
	snmpTimeout int
	readKey     string
	writeKey    string
	scanResult  int
	retries     int
	period      int
}

type SnmpProbe struct {
	Graph              *graph.Graph
	SnmpRoot           *graph.Node
	Root               *graph.Node
	state              int64
	TopologyDetectChan chan *TopologyDetect
}

type SnmpLink struct {
	Name    string
	IfIndex int64
	Type    string
}

var confInfo = &snmpConf{
	coreIp:      "192.168.1.34",
	port:        161,
	scanLayer:   5,
	snmpVersion: 2,
	icmpTimeout: 5,
	snmpTimeout: 5,
	readKey:     "public",
	writeKey:    "private",
	retries:     1,
	period:      1,
}

type topoRelation struct {
	topoLayer   int
	hostId      int
	devName     string
	devIp       string
	devMask     string
	preIp       string
	devType     int
	readKey     string
	snmpVersion int
}

type ipIntfAddrTable struct {
	name      string
	ip        string
	mask      string
	ifindex   int
	ifType    string
	encapType string
	MAC       string
	MTU       int
	driver    string
	state     string
}

type vlanTable struct {
	name          string
	ip            string
	mask          string
	ifindex       int
	vid           uint
	MAC           string
	state         string
	untaggedPorts []int
	taggedPorts   []int
}

type ipRouteTable struct {
	dest      string
	mask      string
	nexthop   string
	ifindex   int
	routeType int
}

type switchArp struct {
	boardSn string
	ip      string
	mac     string
	ifindex int
}

type switchFdb struct {
	boardSn string
	ifindex int
	vlan    int
	mac     string
}

type switchBaseIntf struct {
	boardSn     string
	name        string
	description string
	ifindex     int
	portType    string
	state       string
	pVid        uint
}

/*
type switchEdge struct {
	ip         string
	readKey    string
	switchType string
}
*/

type switchLldp struct {
	ifindex    int
	localPort  string
	remotePort string
	chassisId  string
	manAddress string
}

type deviceInfo struct {
	name         string
	boardSn      string
	info         string
	managementIp string
	switchMac    string
	layer        int
	root         bool
	baseIntfMap  map[int]*switchBaseIntf
	lldpMap      map[int]*switchLldp
	intfIpMap    map[string]*ipIntfAddrTable
	arpMap       map[string]*switchArp
	fdbMap       map[string]*switchFdb
	routeMap     map[string]*ipRouteTable
	vlanMap      map[uint]*vlanTable

	rootNode     *graph.Node
	rootSnmpNode *snmpNode
	nodeMap      map[string]*snmpNode
}

type snmpNode struct {
	id          graph.Identifier
	metadata    graph.Metadata
	node        *graph.Node
	root        bool
	hostId      graph.Identifier
	name        string
	ifindex     int
	state       string
	ifType      string
	ip          string
	info        string
	description string
	pVid        uint

	vlanName    string
	vlanIp      string
	vlanMask    string
	vlanState   string
	vlanIfindex int

	hostInfo string
}

type snmpEdge struct {
	localAddress  string
	localPort     string
	remoteAddress string
	remotePort    string
	info          string
}

type TopologyDetect struct {
	IP        string
	Period    int64
	Community string
}

type snmpConfig struct {
	Detectip     string
	Detectperiod int
	Community    string
}

var TopologyDetectChan chan *TopologyDetect
var deviceInfoMap map[string]*deviceInfo

var TopoRelationMap map[string]*topoRelation
var ipIntfAddrTableMap map[string]*ipIntfAddrTable
var ipRouteTableMap map[string]*ipRouteTable

var switchMac2ManagementIp map[string]string

var directNexhopMap map[string]string
var nodeMap map[string]*snmpNode
var oldNodeMap map[string]*snmpNode
var edgeMap map[string]*snmpEdge

var scanDeviceIp string
var basePort []int
var hostId int
var boardSnProbe string
var scanTicker *time.Ticker

func trace() {
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	fmt.Printf("%s:%d %s\n", file, line, f.Name())
}

func getDeviceNameSwitchMAC(ipAddr string, port uint16) (string, string, string, error) {

	var switchMac, deviceName string

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      port,
		Community: confInfo.readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return "", "", "", err
	}
	defer params.Conn.Close()

	oids := []string{OidSysName}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("Get() err: %v", err)
		return "", "", "", err
	}

	variable := result.Variables[0]
	deviceName = string(variable.Value.([]byte))

	oids = []string{OidDot1dBaseBridgeAddress}
	result, err = params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("Get() err: %v", err)
		return "", "", "", err
	}

	variable = result.Variables[0]
	switchMacStr := variable.Value.([]byte)

	switchMac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", switchMacStr[0], switchMacStr[1], switchMacStr[2], switchMacStr[3], switchMacStr[4], switchMacStr[5])
	fmt.Printf("switchMac %s\n", switchMac)

	boardSnProbe = ipAddr + "-" + switchMac

	return deviceName, switchMac, confInfo.readKey, nil
}

func getDeviceType(ipAddr string, port uint16) (int, error) {

	var err error
	var result *gosnmp.SnmpPacket
	var oids []string
	//var oid string
	var variable gosnmp.SnmpPDU
	var flagBridgeMib bool
	var flagForwarding bool

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      port,
		Community: confInfo.readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:  log.New(os.Stdout, "", 0),
	}

	err = params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return 0, err
	}
	defer params.Conn.Close()

	/* forwarding */
	oids = []string{OidIpForwarding}
	result, err = params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("Get() err: %v", err)
		return 0, err
	}

	variable = result.Variables[0]
	ipForwarding := variable.Value

	if ipForwarding == 1 {
		flagForwarding = true
	}

	/*bridge-mib just for switch*/
	oids = []string{OidBaseNumPorts}
	result, err = params.Get(oids)
	if err == nil {
		oids = []string{OidBaseNumPorts}
		result, err = params.Get(oids)
		if err == nil {
			oids = []string{OidStpRootCost}
			result, err = params.Get(oids)
			if err == nil {
				oids = []string{OidStpRootPort}
				result, err = params.Get(oids)
				if err == nil {
					flagBridgeMib = true
					logging.GetLogger().Debugf("Ip (%s) is bridge device", ipAddr)

					/*
						oid = OidTpFdbPort
						err = params.Walk(oid, doNothing)
						if err == nil {
							logging.GetLogger().Debugf("Walk OidTpFdbPort success")
						} else {
							oid = OidTpFdb2Port
							err = params.Walk(oid, doNothing)
							if err == nil {
								logging.GetLogger().Debugf("Walk OidTpFdb2Port success")
							}
						}
					*/
				}
			}
		}
	}

	if flagForwarding && flagBridgeMib {
		return SwitchL3Type, nil
	} else if flagForwarding {
		return RouteType, nil
	} else if flagBridgeMib {
		return SwitchL2SnmpType, nil
	}

	return 0, nil
}

func doNothing(pdu gosnmp.SnmpPDU) error {
	return nil
}

func printValue(pdu gosnmp.SnmpPDU) error {
	fmt.Printf("%s = ", pdu.Name)

	switch pdu.Type {
	case gosnmp.OctetString:
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", string(b))
	default:
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}
	return nil
}

func storeTopo2Map(ipAddr string, topoRe *topoRelation) int {
	logging.GetLogger().Debugf("storeTopo2Map ip:%s", ipAddr)
	if _, ok := TopoRelationMap[ipAddr]; ok {
		logging.GetLogger().Debugf("The ip(%s) is exist in TopoRelationMap", ipAddr)
	} else {
		TopoRelationMap[ipAddr] = topoRe
	}

	return 0
}

func storeDeviceInfo2Map(boardSn string, device *deviceInfo) error {
	logging.GetLogger().Debugf("storeDeviceInfo2Map boardSn:%s, ip:%s", boardSn, device.managementIp)
	if _, ok := deviceInfoMap[boardSn]; ok {
		logging.GetLogger().Debugf("The boardSn:%s is exist in deviceInfoMap", boardSn)
		return errors.New("boardSn exist")
	} else {
		deviceInfoMap[boardSn] = device
	}

	return nil
}

func getDeviceInfo(ipAddr string, readKey *string, layer int) (int, error) {

	deviceName, switchMac, readKeyFind, err := getDeviceNameSwitchMAC(ipAddr, confInfo.port)
	if err != nil {
		return UnknownType, err
	}
	logging.GetLogger().Debugf("IP %s name: %s, switchMac: %s, readkey: %s", ipAddr, deviceName, switchMac, readKeyFind)

	deviceType, err := getDeviceType(ipAddr, confInfo.port)
	if err != nil {
		return UnknownType, nil
	}
	logging.GetLogger().Debugf("IP %s device type: %d", ipAddr, deviceType)

	*readKey = readKeyFind

	var device *deviceInfo = new(deviceInfo)
	device.name = deviceName
	device.boardSn = boardSnProbe
	device.switchMac = switchMac
	device.layer = layer
	if ipAddr == confInfo.coreIp {
		device.root = true
	}

	device.baseIntfMap = make(map[int]*switchBaseIntf)
	device.lldpMap = make(map[int]*switchLldp)
	device.intfIpMap = make(map[string]*ipIntfAddrTable)
	device.vlanMap = make(map[uint]*vlanTable)
	/*
		device.arpMap = make(map[string]*switchArp)
		device.fdbMap = make(map[string]*switchFdb)
		device.routeMap = make(map[string]*ipRouteTable)
	*/
	device.managementIp = ipAddr
	device.info = device.managementIp + "(" + device.switchMac + ")"

	err = storeDeviceInfo2Map(boardSnProbe, device)

	return deviceType, err
}

func isValidIp(ipAddr string) bool {
	return "127.0.0.1" != ipAddr && "0.0.0.0" != ipAddr && "255.0.0.0" != ipAddr && "" != ipAddr
}

func getIntfIndexByIp(deviceIp string, ipAddr string, ifindex *int) error {
	var oid string
	readKey := confInfo.readKey

	/*
		IP-MIB::ipAdEntIfIndex.10.0.0.254 = INTEGER: 3718
		IP-MIB::ipAdEntIfIndex.10.0.1.254 = INTEGER: 3846
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIpIfindex + "." + ipAddr
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the ifindex of ip(%s) fail, err %s", ipAddr, err)
		return err
	}

	variable := result.Variables[0]
	*ifindex = variable.Value.(int)

	logging.GetLogger().Debugf("get the ifindex (%d) of ip(%s) success\n", *ifindex, ipAddr)

	return nil
}

func getIntfNameByIndex(deviceIp string, ifindex int, name *string) error {
	var oid string
	readKey := confInfo.readKey

	/*
		IF-MIB::ifOperStatus.10004 = INTEGER: up(1)
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()
	oid = OidIfDescr + "." + strconv.Itoa(ifindex)
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the name of intf index %d ip(%s) fail, err %s", ifindex, deviceIp, err)
		return err
	}

	variable := result.Variables[0]
	*name = string(variable.Value.([]byte))

	logging.GetLogger().Debugf("get the name type (%x)\n", variable.Type)
	logging.GetLogger().Debugf("get the name(%s) of intf index %d ip(%s) success\n", *name, ifindex, deviceIp)

	return nil
}

func getIntfMacByIndex(deviceIp string, ifindex int, intfMac *string) error {
	var oid string
	readKey := confInfo.readKey

	/*
		IF-MIB::ifPhysAddress.10004 = STRING: 0:3:f:64:da:5f
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIfPhyAddr + "." + strconv.Itoa(ifindex)
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the mac of intf index %d ip(%s) fail, err %s", ifindex, deviceIp, err)
		return err
	}

	variable := result.Variables[0]
	mac := variable.Value.([]byte)
	macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	fmt.Printf("ifindex %d\n", ifindex)
	fmt.Printf("MAC %s\n", macStr)

	*intfMac = macStr

	return nil
}

func getIntfStatusByIndex(deviceIp string, ifindex int, state *string) error {
	var oid string
	readKey := confInfo.readKey

	/*
		IF-MIB::ifOperStatus.10004 = INTEGER: up(1)
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIfOperStatus + "." + strconv.Itoa(ifindex)
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the status of intf index %d ip(%s) fail, err %s", ifindex, deviceIp, err)
		return err
	}

	variable := result.Variables[0]
	upStatus := variable.Value.(int)

	if upStatus == 1 {
		*state = "UP"
	} else {
		*state = "DOWN"
	}

	logging.GetLogger().Debugf("get the status(%s) of intf index %d ip(%s) success\n", *state, ifindex, deviceIp)

	return nil
}

func getIntfMaskByIp(deviceIp string, ipAddr string, mask *string) error {
	var oid string
	readKey := confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIpMask + "." + ipAddr

	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the mask of ip(%s) fail, err %s", ipAddr, err)
		return err
	}

	variable := result.Variables[0]
	*mask = variable.Value.(string)

	logging.GetLogger().Debugf("get the mask (%s) of ip(%s) success\n", *mask, ipAddr)

	return nil
}

func storeIntfIpMask2Map(ipAddr string, ipIntf *ipIntfAddrTable) int {
	logging.GetLogger().Debugf("storeIntfIpMask2Map boardSn:%s intf ip:%s", boardSnProbe, ipIntf.ip)
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.intfIpMap[ipAddr]; ok {
			logging.GetLogger().Debugf("The ip(%s) is exist in storeIntfIpMask2Map", ipAddr)
		} else {
			deviceInfo.intfIpMap[ipAddr] = ipIntf
		}
	}

	return 0
}

func getDevIntfIpTableCallback(pdu gosnmp.SnmpPDU) error {

	var ifindex int

	if pdu.Value == nil {
		logging.GetLogger().Debugf("has no intf ip")
		return nil
	}

	if pdu.Type != gosnmp.IPAddress {
		logging.GetLogger().Errorf("pdu type is not IPAddress")
		return nil
	}

	ip := pdu.Value.(string)
	logging.GetLogger().Debugf("get interface IPAddress: %s\n", ip)

	if !isValidIp(ip) {
		logging.GetLogger().Errorf("IPAddress: %s is not valid\n", ip)
		return nil
	}

	var mask string
	err := getIntfMaskByIp(scanDeviceIp, ip, &mask)
	if err != nil {
		return err
	}

	err = getIntfIndexByIp(scanDeviceIp, ip, &ifindex)
	if err != nil {
		return err
	}

	var name string
	err = getIntfNameByIndex(scanDeviceIp, ifindex, &name)
	if err != nil {
		return err
	}

	/*
		var mac string
		err = getIntfMacByIndex(scanDeviceIp, ifindex, &mac)
		if err != nil {
			return err
		}
	*/

	var state string
	err = getIntfStatusByIndex(scanDeviceIp, ifindex, &state)
	if err != nil {
		return err
	}

	var ipIntf *ipIntfAddrTable = new(ipIntfAddrTable)

	ipIntf.name = name
	ipIntf.ip = ip
	ipIntf.mask = mask
	ipIntf.ifindex = ifindex
	ipIntf.ifType = "device"
	ipIntf.encapType = "ether"
	ipIntf.MTU = 1518
	ipIntf.driver = "tg3"
	ipIntf.state = state

	storeIntfIpMask2Map(ip, ipIntf)

	return nil
}

func getDevIntfIpTable(ipAddr string, readKey *string) error {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIpAddr
	err = params.Walk(oid, getDevIntfIpTableCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the ip mask of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the ip mask of ip(%s) error(%s)", ipAddr, err)
	}

	return err
}

func getRouteIndexByDest(deviceIp string, destIp string, ifindex *int) error {
	var oid string
	readKey := confInfo.readKey

	/*
		IP-MIB::ip.21.1.2.11.11.11.0 = INTEGER: 10011
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidRouteIfindex + "." + destIp
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the ifindex of destIp(%s) fail, err %s", destIp, err)
		return err
	}

	variable := result.Variables[0]
	*ifindex = variable.Value.(int)

	logging.GetLogger().Debugf("get the ifindex (%d) of destIp(%s) success\n", *ifindex, destIp)

	return nil
}

func getRouteNexthopByDest(deviceIp string, destIp string, nexthop *string) error {
	var oid string
	readKey := confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidRouteNexthop + "." + destIp
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the nexthop of destIp(%s) fail, err %s", destIp, err)
		return err
	}

	variable := result.Variables[0]
	*nexthop = variable.Value.(string)

	logging.GetLogger().Debugf("get the nexthop(%s) of destIp(%s) success\n", *nexthop, destIp)

	return nil
}

func getRouteMaskByDest(deviceIp string, destIp string, mask *string) error {
	var oid string
	readKey := confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidRouteMask + "." + destIp
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the mask of destIp(%s) fail, err %s", destIp, err)
		return err
	}

	variable := result.Variables[0]
	*mask = variable.Value.(string)

	logging.GetLogger().Debugf("get the mask (%s) of destIp(%s) success\n", *mask, destIp)

	return nil
}

func getRouteTypeByDest(deviceIp string, destIp string, routeType *int) error {
	var oid string
	readKey := confInfo.readKey

	/*
		P-MIB::ip.21.1.8.11.11.11.0 = INTEGER: 3
	*/

	params := &gosnmp.GoSNMP{
		Target:    deviceIp,
		Port:      confInfo.port,
		Community: readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidRouteType + "." + destIp
	oids := []string{oid}
	result, err := params.Get(oids)
	if err != nil {
		logging.GetLogger().Errorf("get the route type of ip(%s) fail, err %s", destIp, err)
		return err
	}

	variable := result.Variables[0]
	*routeType = variable.Value.(int)

	logging.GetLogger().Debugf("get the route type (%d) of ip(%s) success\n", *routeType, destIp)

	return nil
}

func storeRoute2MapOld(destIp string, ipRoute *ipRouteTable) int {
	logging.GetLogger().Debugf("storeRoute2Map destIp:%s", destIp)
	if _, ok := ipRouteTableMap[destIp]; ok {
		logging.GetLogger().Debugf("The destIp(%s) is exist", destIp)
	} else {
		ipRouteTableMap[destIp] = ipRoute
	}

	return 0
}

func storeRoute2Map(destIp string, ipRoute *ipRouteTable) int {
	logging.GetLogger().Debugf("storeRoute2Map destIp:%s", destIp)
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.routeMap[destIp]; ok {
			logging.GetLogger().Debugf("The destIp(%s) is exist in storeFdbInfo2Map", destIp)
		} else {
			deviceInfo.routeMap[destIp] = ipRoute
		}
	}

	return 0
}

func getDevRouteTableCallback(pdu gosnmp.SnmpPDU) error {

	fmt.Printf("getDevRouteTableCallback\n")

	if pdu.Type != gosnmp.IPAddress {
		logging.GetLogger().Errorf("pdu type is not IPAddress")
		return nil
	}

	ip := pdu.Value.(string)
	logging.GetLogger().Debugf("get route destIp %s", ip)

	/* default route
	if !isValidIp(ip) {
		logging.GetLogger().Errorf("IPAddress: %s is not valid\n", ip)
		return nil
	}
	*/

	var ifindex int
	err := getRouteIndexByDest(scanDeviceIp, ip, &ifindex)
	if err != nil {
		return err
	}

	var nexthop string
	err = getRouteNexthopByDest(scanDeviceIp, ip, &nexthop)
	if err != nil {
		return err
	}

	var mask string
	err = getRouteMaskByDest(scanDeviceIp, ip, &mask)
	if err != nil {
		return err
	}

	var routeType int
	err = getRouteTypeByDest(scanDeviceIp, ip, &routeType)
	if err != nil {
		return err
	}

	var ipRoute *ipRouteTable = new(ipRouteTable)

	ipRoute.dest = ip
	ipRoute.mask = mask
	ipRoute.nexthop = nexthop
	ipRoute.ifindex = ifindex
	ipRoute.routeType = routeType

	storeRoute2Map(ip, ipRoute)

	return nil
}

func getDevRouteTable(ipAddr string, readKey *string) {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		//Logger:    log.New(os.Stdout, "", 0),
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return
	}
	defer params.Conn.Close()

	oid = OidRouteDest
	err = params.Walk(oid, getDevRouteTableCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the route table of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the route table of ip(%s) error(%s)", ipAddr, err)
	}
}

func storeDirectNexthop2Map(nexthop string) int {
	logging.GetLogger().Debugf("storeDirectNexthop2Map ip:%s", nexthop)
	if _, ok := directNexhopMap[nexthop]; ok {
		logging.GetLogger().Debugf("The nexthop(%s) is exist in directNexhopMap", nexthop)
	} else {
		directNexhopMap[nexthop] = nexthop
	}

	return 0
}

func getIntfIpbyIndex(ipAddr string, ifindex int) (string, error) {
	if device, ok := deviceInfoMap[boardSnProbe]; ok {
		for _, intfIp := range device.intfIpMap {
			if intfIp.ifindex == ifindex {
				ip := intfIp.ip
				logging.GetLogger().Debugf("find ifindex %d IP: %s", ifindex, ip)
				return ip, nil
			}
		}
	}
	return "", errors.New("fail")
}

func getNexthopInfo(scanLayer int, ipAddr string, ipRoute *ipRouteTable) {

	logging.GetLogger().Debugf("getNexthopInfo of nexthop(%s)", ipRoute.nexthop)

	deviceName, readKeyFind, snmpVersion, err := getDeviceNameSwitchMAC(ipRoute.nexthop, confInfo.port)
	if err != nil {
		logging.GetLogger().Error("getDeviceNameSwitchMAC of nexthop(%s) fail", ipRoute.nexthop)
		return
	}
	logging.GetLogger().Debugf("IP %s name: %s, readkey: %s, snmpVersion: %s", ipRoute.nexthop, deviceName, readKeyFind, snmpVersion)

	deviceType, err := getDeviceType(ipRoute.nexthop, confInfo.port)
	if err != nil {
		logging.GetLogger().Error("getDeviceType of nexthop(%s) fail", ipRoute.nexthop)
		return
	}
	logging.GetLogger().Debugf("IP %s device type: %d", ipRoute.nexthop, deviceType)

	preIp, err := getIntfIpbyIndex(ipAddr, ipRoute.ifindex)
	if err != nil {
		logging.GetLogger().Error("getIntfIpbyIndex of ifindex %d fail", ipRoute.ifindex)
		return
	}

	var topoRe *topoRelation = new(topoRelation)

	topoRe.topoLayer = scanLayer
	topoRe.devName = deviceName
	topoRe.devIp = ipRoute.nexthop
	topoRe.preIp = preIp
	topoRe.readKey = confInfo.readKey
	topoRe.devType = deviceType

	storeTopo2Map(ipRoute.nexthop, topoRe)
}

func printIpRoute(ipRoute *ipRouteTable) {
	logging.GetLogger().Debugf("range dest %s", ipRoute.dest)
	logging.GetLogger().Debugf("      mask %s", ipRoute.mask)
	logging.GetLogger().Debugf("      nexthop %s", ipRoute.nexthop)
	logging.GetLogger().Debugf("      ifindex %d", ipRoute.ifindex)
	logging.GetLogger().Debugf("      route type %d", ipRoute.routeType)
}

func printAllDeviceInfo() {
	logging.GetLogger().Debugf("printAllDeviceInfo")
	for _, deviceInfo := range deviceInfoMap {
		printDeviceInfo(deviceInfo)
	}
}

func storeLldpInfo2Map(ifindex int, lldpInfo *switchLldp) int {
	var port string
	logging.GetLogger().Debugf("storeLldpInfo2Map boardSn:%s ifindex:%d", boardSnProbe, ifindex)
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.lldpMap[ifindex]; ok {
			logging.GetLogger().Debugf("The ifindex(%d) is exist in storeLldpInfo2Map", ifindex)
		} else {
			if switchBaseIntf, ok := deviceInfo.baseIntfMap[ifindex]; ok {
				port = switchBaseIntf.name
			}
			lldpInfo.localPort = port
			deviceInfo.lldpMap[ifindex] = lldpInfo
		}
	}

	return 0
}

func getLldpRemChassisIdCallback(pdu gosnmp.SnmpPDU) error {

	mac := string(pdu.Value.([]byte))

	if len(mac) == 0 {
		return nil
	}

	markNumIndexStr := strings.TrimPrefix(pdu.Name, OidLldpRemChassisId+".")
	markNumIndex := strings.SplitN(markNumIndexStr, ".", 3)

	ifindex, err := strconv.Atoi(markNumIndex[2])
	if err != nil {
		return err
	}

	fmt.Printf("ifindex %d\n", ifindex)
	fmt.Printf("MAC %s\n", mac)

	var lldpInfo *switchLldp = new(switchLldp)
	lldpInfo.ifindex = ifindex
	lldpInfo.chassisId = mac

	storeLldpInfo2Map(ifindex, lldpInfo)

	return nil
}

func storeLldpRemPortId(ifindex int, port string) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if lldpInfo, ok := deviceInfo.lldpMap[ifindex]; ok {
			lldpInfo.remotePort = port
		} else {
			logging.GetLogger().Errorf("Find ifindex(%d) in storeLldpRemPortId fail", ifindex)
		}
	}

	return 0
}

func getLldpRemPortIdCallback(pdu gosnmp.SnmpPDU) error {
	port := string(pdu.Value.([]byte))

	if port == "" {
		return nil
	}

	markNumIndexStr := strings.TrimPrefix(pdu.Name, OidLldpRemPortId+".")
	markNumIndex := strings.SplitN(markNumIndexStr, ".", 3)

	ifindex, err := strconv.Atoi(markNumIndex[2])
	if err != nil {
		return err
	}

	storeLldpRemPortId(ifindex, port)

	return nil
}

func storeLldpRemManAddr(ifindex int, manAddress string) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if lldpInfo, ok := deviceInfo.lldpMap[ifindex]; ok {
			if !isValidIp(manAddress) {
				return 0
			}
			lldpInfo.manAddress = manAddress
			//switchMac2ManagementIp[lldpInfo.chassisId] = manAddress
		} else {
			logging.GetLogger().Errorf("Find ifindex(%d) in lldpMap fail", ifindex)
		}
	}

	return 0
}

func storeLldpLocalManAddr(manAddress string) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if deviceInfo.managementIp != "" && deviceInfo.managementIp != manAddress {
			logging.GetLogger().Errorf("Get different managementIp (%s) in deive %s with %s", manAddress, deviceInfo.name, deviceInfo.managementIp)
			return -1
		}
		deviceInfo.managementIp = manAddress
		//deviceInfo.info = deviceInfo.managementIp + "(" + deviceInfo.switchMac + ")"
	}

	return 0
}

func getLldpRemManAddrIfIdCallback(pdu gosnmp.SnmpPDU) error {

	if pdu.Value == nil {
		fmt.Println("getLldpRemManAddrIfIdCallback Value nil")
		return nil
	}

	remManAddrStr := strings.TrimPrefix(pdu.Name, OidLldpRemManAddrIfId+".")
	remManAddrStrSplit := strings.SplitN(remManAddrStr, ".", 5)

	ifindex, err := strconv.Atoi(remManAddrStrSplit[2])
	if err != nil {
		return err
	}

	/*
		if !isValidIp(manAddress) {
			logging.GetLogger().Errorf("LLDP get remote manAddress of ifindex %d is 0.0.0.0", ifindex)
			return errors.New("zero address")
		}
	*/

	manAddress := remManAddrStrSplit[4]

	storeLldpRemManAddr(ifindex, manAddress)

	return nil
}

func getLldpLocalManAddrIfIdCallback(pdu gosnmp.SnmpPDU) error {
	localManAddrStr := strings.TrimPrefix(pdu.Name, OidLldpLocalManAddrIfId+".")
	localManAddrStrSplit := strings.SplitN(localManAddrStr, ".", 2)

	manAddress := localManAddrStrSplit[1]

	if !isValidIp(manAddress) {
		return nil
	}

	storeLldpLocalManAddr(manAddress)

	return nil
}

func getLldpInfo(ipAddr string, readKey *string) error {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidLldpLocalManAddrIfId
	err = params.Walk(oid, getLldpLocalManAddrIfIdCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the local managementIp ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the local managementIp of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidLldpRemChassisId
	err = params.Walk(oid, getLldpRemChassisIdCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the remote chassisId ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the remote chassisId of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidLldpRemPortId
	err = params.Walk(oid, getLldpRemPortIdCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the remote port of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the remote port of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidLldpRemManAddrIfId
	err = params.Walk(oid, getLldpRemManAddrIfIdCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the remote managementIp of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the remote managementIp of ip(%s) error(%s)", ipAddr, err)
	}

	return err
}

func storeBaseIntf2Map(ifindex int, baseIntf *switchBaseIntf) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.baseIntfMap[ifindex]; ok {
			logging.GetLogger().Debugf("The ifindex(%d) is exist in storeBaseIntf2Map", ifindex)
		} else {
			deviceInfo.baseIntfMap[ifindex] = baseIntf
		}
	}

	return 0
}

func getBaseIntfCallback(pdu gosnmp.SnmpPDU) error {

	ifindexStr := strings.TrimPrefix(pdu.Name, OidIfDescr+".")
	ifindex, _ := strconv.Atoi(ifindexStr)
	name := string(pdu.Value.([]byte))

	var baseIntf *switchBaseIntf = new(switchBaseIntf)
	baseIntf.ifindex = ifindex
	baseIntf.name = name
	baseIntf.pVid = 1

	storeBaseIntf2Map(ifindex, baseIntf)

	return nil
}

func getBaseIntfDescCallback(pdu gosnmp.SnmpPDU) error {

	ifindexStr := strings.TrimPrefix(pdu.Name, OidIfAlias+".")
	ifindex, _ := strconv.Atoi(ifindexStr)
	description := string(pdu.Value.([]byte))

	deviceInfo, _ := deviceInfoMap[boardSnProbe]
	deviceInfo.baseIntfMap[ifindex].description = description

	return nil
}

func storeBaseIntfPvid2Map(ifindex int, pvid uint) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.baseIntfMap[ifindex]; ok {
			deviceInfo.baseIntfMap[ifindex].pVid = pvid
		} else {
			logging.GetLogger().Errorf("The ifindex(%d) is not exist in baseIntfMap", ifindex)
		}
	}

	return 0
}

func getBaseIntfPvidCallback(pdu gosnmp.SnmpPDU) error {

	ifindexStr := strings.TrimPrefix(pdu.Name, OidDot1qPvid+".")
	ifindex, _ := strconv.Atoi(ifindexStr)
	pvid := pdu.Value.(uint)

	deviceInfo, _ := deviceInfoMap[boardSnProbe]
	deviceInfo.baseIntfMap[ifindex].pVid = pvid

	return nil
}

func storeBaseIntfStatus2Map(ifindex int, state string) {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.baseIntfMap[ifindex]; ok {
			deviceInfo.baseIntfMap[ifindex].state = state
		} else {
			logging.GetLogger().Errorf("The ifindex(%d) is not exist in baseIntfMap", ifindex)
		}
	}
}

func getBaseIntfStatusCallback(pdu gosnmp.SnmpPDU) error {

	var state string

	ifindexStr := strings.TrimPrefix(pdu.Name, OidIfOperStatus+".")
	ifindex, _ := strconv.Atoi(ifindexStr)
	status := pdu.Value.(int)

	if status == 1 {
		state = "UP"
	} else {
		state = "DOWN"
	}

	deviceInfo, _ := deviceInfoMap[boardSnProbe]
	deviceInfo.baseIntfMap[ifindex].state = state

	return nil
}

func getBaseIntf(ipAddr string, readKey *string) error {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidIfDescr
	err = params.Walk(oid, getBaseIntfCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the base interface of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the base interface of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidIfAlias
	err = params.Walk(oid, getBaseIntfDescCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the base interface description of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the base interface description of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidDot1qPvid
	err = params.Walk(oid, getBaseIntfPvidCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the port pvid of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the port pvid of ip(%s) error(%s)", ipAddr, err)
	}

	oid = OidIfOperStatus
	err = params.Walk(oid, getBaseIntfStatusCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the port status of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the port status of ip(%s) error(%s)", ipAddr, err)
	}

	return err
}

func getVlanIntfCallback(pdu gosnmp.SnmpPDU) error {

	markIndexStr := strings.TrimPrefix(pdu.Name, OidDot1qVlanFdbId+".")
	indexStr := strings.SplitN(markIndexStr, ".", 2)
	ifindex, _ := strconv.Atoi(indexStr[1])

	vid := pdu.Value.(uint)

	var vlanInfo *vlanTable = new(vlanTable)
	vlanInfo.ifindex = ifindex
	vlanInfo.vid = vid

	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		for _, intfIp := range deviceInfo.intfIpMap {
			if intfIp.ifindex == ifindex {
				vlanInfo.name = intfIp.name
				vlanInfo.ip = intfIp.ip
				vlanInfo.mask = intfIp.mask
				vlanInfo.state = intfIp.state
			}
		}
		deviceInfo.vlanMap[vid] = vlanInfo
	}

	return nil
}
func getVlanIntf(ipAddr string, readKey *string) error {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return err
	}
	defer params.Conn.Close()

	oid = OidDot1qVlanFdbId
	err = params.Walk(oid, getVlanIntfCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the vlan table of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the vlan table of ip(%s) error(%s)", ipAddr, err)
	}

	return err
}

func deviceScan(scanLayer int, ipAddr string) (int, error) {
	var readKeyFind string

	logging.GetLogger().Errorf("**************scan layer %d ip %s begin***************", scanLayer, ipAddr)

	if ip := net.ParseIP(ipAddr); ip == nil {
		logging.GetLogger().Errorf("ip %s is invalid", ipAddr)
		return 0, nil
	}

	for _, deviceInfo := range deviceInfoMap {
		if deviceInfo.managementIp == ipAddr {
			logging.GetLogger().Debugf("ip %s has been already scanned", ipAddr)
			logging.GetLogger().Errorf("**************scan layer %d ip %s end***************", scanLayer, ipAddr)
			return 0, nil
		}
	}

	_, err := getDeviceInfo(ipAddr, &readKeyFind, scanLayer)
	if err != nil {
		logging.GetLogger().Errorf("**************scan layer %d ip %s end***************", scanLayer, ipAddr)
		return 0, err
	}

	getBaseIntf(ipAddr, &readKeyFind)

	getLldpInfo(ipAddr, &readKeyFind)

	getDevIntfIpTable(ipAddr, &readKeyFind)

	getVlanIntf(ipAddr, &readKeyFind)

	/*
				if deviceType == SwitchL3Type || deviceType == RouteType {
					getArpInfo(ipAddr, &readKeyFind)
				}

				if deviceType == SwitchL3Type || deviceType == SwitchL2SnmpType {
					getFdbInfo(ipAddr, &readKeyFind)
				}

				getDevRouteTable(ipAddr, &readKeyFind)
			ipRouteTableMap = make(map[string]*ipRouteTable)
		ipIntfAddrTableMap = make(map[string]*ipIntfAddrTable)
	*/

	logging.GetLogger().Errorf("**************scan layer %d ip %s end***************", scanLayer, ipAddr)

	return 0, nil
}

func printTopoRelation(topoRe *topoRelation) {
	logging.GetLogger().Debugf("range topoLayer %d", topoRe.topoLayer)
	logging.GetLogger().Debugf("      devName %s", topoRe.devName)
	logging.GetLogger().Debugf("      devIp %s", topoRe.devIp)
	logging.GetLogger().Debugf("      mask %s", topoRe.devMask)
	logging.GetLogger().Debugf("      preIp %s", topoRe.preIp)
	logging.GetLogger().Debugf("      devType %d", topoRe.devType)
	logging.GetLogger().Debugf("      readKey %s", topoRe.readKey)
	logging.GetLogger().Debugf("      route snmpVersion %d", topoRe.snmpVersion)
}

func printDeviceInfo(deviceInfo *deviceInfo) {

	logging.GetLogger().Errorf("deviceInfo name %s", deviceInfo.name)
	logging.GetLogger().Debugf("           boardSn %s", deviceInfo.boardSn)
	logging.GetLogger().Debugf("           managementIp %s", deviceInfo.managementIp)
	logging.GetLogger().Debugf("           switchMac %s", deviceInfo.switchMac)
	logging.GetLogger().Debugf("           info %s", deviceInfo.info)
	logging.GetLogger().Debugf("           root %t", deviceInfo.root)
	logging.GetLogger().Debugf("           layer %d", deviceInfo.layer)

	/*
		for _, baseIntf := range deviceInfo.baseIntfMap {
				logging.GetLogger().Debugf("BaseIntf   ifindex %d", baseIntf.ifindex)
				logging.GetLogger().Debugf("           name %s", baseIntf.name)
		}
	*/

	for _, lldpInfo := range deviceInfo.lldpMap {
		logging.GetLogger().Debugf("lldpInfo   ifindex %d", lldpInfo.ifindex)
		logging.GetLogger().Debugf("           localPort %s", lldpInfo.localPort)
		logging.GetLogger().Debugf("           remotePort %s", lldpInfo.remotePort)
		logging.GetLogger().Debugf("           chassisId %s", lldpInfo.chassisId)
		logging.GetLogger().Debugf("           manAddress %s", lldpInfo.manAddress)
	}

	/*
		for _, intfIp := range deviceInfo.intfIpMap {
			logging.GetLogger().Debugf("intfIp     name %s", intfIp.name)
			logging.GetLogger().Debugf("           ip %s", intfIp.ip)
			logging.GetLogger().Debugf("           mask %s", intfIp.mask)
			logging.GetLogger().Debugf("           ifindex %d", intfIp.ifindex)
			logging.GetLogger().Debugf("           MAC %s", intfIp.MAC)
			logging.GetLogger().Debugf("           state %s", intfIp.state)
		}

		for _, arpInfo := range deviceInfo.arpMap {
			logging.GetLogger().Debugf("arpInfo    ip %s", arpInfo.ip)
			logging.GetLogger().Debugf("           mac %s", arpInfo.mac)
			logging.GetLogger().Debugf("           ifindex %d", arpInfo.ifindex)
		}
		for _, fdbInfo := range deviceInfo.fdbMap {
			logging.GetLogger().Debugf("fdbInfo    mac %s", fdbInfo.mac)
			logging.GetLogger().Debugf("           ifindex %d", fdbInfo.ifindex)
		}
		for _, ipRoute := range deviceInfo.routeMap {
			logging.GetLogger().Debugf("routeInfo  dest %s", ipRoute.dest)
			logging.GetLogger().Debugf("           mask %s", ipRoute.mask)
			logging.GetLogger().Debugf("           nexthop %s", ipRoute.nexthop)
			logging.GetLogger().Debugf("           ifindex %d", ipRoute.ifindex)
			logging.GetLogger().Debugf("           route type %d", ipRoute.routeType)
		}
	*/
}

func scanLayerDevice(scanLayer int) int {

	var i, j int
	logging.GetLogger().Debugf("get neighbor ip from level %d", scanLayer-1)
	for _, deviceInfo := range deviceInfoMap {
		i++
		logging.GetLogger().Debugf("printDeviceInfo count  %d", i)
		logging.GetLogger().Errorf("deviceInfo name %s", deviceInfo.name)
		logging.GetLogger().Debugf("           info %s", deviceInfo.info)
		logging.GetLogger().Debugf("           layer %d", deviceInfo.layer)
		if deviceInfo.layer != scanLayer-1 {
			continue
		}
		for _, lldpInfo := range deviceInfo.lldpMap {
			j++
			logging.GetLogger().Debugf("lldpInfo count %d of device %s", j, deviceInfo.managementIp)
			logging.GetLogger().Debugf("           ifindex %d", lldpInfo.ifindex)
			logging.GetLogger().Debugf("           localPort %s", lldpInfo.localPort)
			logging.GetLogger().Debugf("           remotePort %s", lldpInfo.remotePort)
			logging.GetLogger().Debugf("           chassisId %s", lldpInfo.chassisId)
			logging.GetLogger().Debugf("           manAddress %s", lldpInfo.manAddress)

			scanIpAddr := lldpInfo.manAddress
			if !isValidIp(scanIpAddr) {
				continue
			}
			if scanIpAddr == deviceInfo.managementIp {
				continue
			}

			logging.GetLogger().Debugf("getScanDeviceIp find ip:%s", scanIpAddr)

			scanDeviceIp = scanIpAddr
			deviceScan(scanLayer, scanIpAddr)
		}

		/*
			for _, arpInfo := range deviceInfo.arpMap {
				scanIpAddr := arpInfo.ip
				logging.GetLogger().Debugf("getScanDeviceIp find ip:%s", scanIpAddr)
				scanDeviceIp = scanIpAddr
				deviceScan(scanLayer, scanIpAddr)
			}
		*/
	}

	return i
}

func storeFdbInfo2Map(mac string, fdbInfo *switchFdb) int {
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.fdbMap[mac]; ok {
			logging.GetLogger().Debugf("The mac(%s) is exist in storeFdbInfo2Map", mac)
		} else {
			deviceInfo.fdbMap[mac] = fdbInfo
		}
	}

	return 0
}

func getFdbInfoCallback(pdu gosnmp.SnmpPDU) error {

	var mac string
	if strings.Contains(pdu.Name, OidTpFdbPort) {
		mac = strings.TrimPrefix(pdu.Name, OidTpFdbPort+".")
	} else {
		mac = strings.TrimPrefix(pdu.Name, OidTpFdb2Port+".")
	}
	if pdu.Value == nil {
		return nil
	}
	ifindex := pdu.Value.(int)
	macTmp := strings.SplitN(mac, ".", 6)

	var macDec [6]int
	macDec[0], _ = strconv.Atoi(macTmp[0])
	macDec[1], _ = strconv.Atoi(macTmp[1])
	macDec[2], _ = strconv.Atoi(macTmp[2])
	macDec[3], _ = strconv.Atoi(macTmp[3])
	macDec[4], _ = strconv.Atoi(macTmp[4])
	macDec[5], _ = strconv.Atoi(macTmp[5])
	macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", macDec[0], macDec[1], macDec[2], macDec[3], macDec[4], macDec[5])

	var fdbInfo *switchFdb = new(switchFdb)
	fdbInfo.mac = macStr
	fdbInfo.ifindex = ifindex

	storeFdbInfo2Map(macStr, fdbInfo)

	return nil
}

/*
func storeSwitchEdge2Map(ipAddr string, edge *switchEdge) {
	logging.GetLogger().Debugf("storeSwitchEdge2Map ip:%s", ipAddr)
	if _, ok := edgeMap[ipAddr]; ok {
		logging.GetLogger().Debugf("The ip(%s) is exist in edgeMap", ipAddr)
	} else {
		edgeMap[ipAddr] = edge
	}
}
*/

func getFdbInfo(ipAddr string, readKey *string) {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return
	}
	defer params.Conn.Close()

	var oidType string

	oid = OidTpFdbPort

retry:
	if oid == OidTpFdbPort {
		oidType = "OidTpFdbPort"
	} else {
		oidType = "OidTpFdb2Port"
	}
	err = params.Walk(oid, getFdbInfoCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the %s table of ip(%s) success", oidType, ipAddr)
	} else {
		logging.GetLogger().Debugf("get the %s table of ip(%s) fail", oidType, ipAddr)
		if oid == OidTpFdbPort {
			oid = OidTpFdb2Port
			logging.GetLogger().Debugf("using OidTpFdbPort retry")
		}
		goto retry
	}
}

func storeArpInfo2Map(ipAddr string, arpInfo *switchArp) int {
	logging.GetLogger().Debugf("storeArpInfo2Map boardSn:%s ip:%s", boardSnProbe, ipAddr)
	if deviceInfo, ok := deviceInfoMap[boardSnProbe]; ok {
		if _, ok = deviceInfo.arpMap[ipAddr]; ok {
			logging.GetLogger().Debugf("The ip(%s) is exist in storeArpInfo2Map", ipAddr)
		} else {
			deviceInfo.arpMap[ipAddr] = arpInfo
		}
	}

	return 0
}

func getArpInfoCallback(pdu gosnmp.SnmpPDU) error {

	if pdu.Value == nil {
		return nil
	}

	mac := pdu.Value.([]byte)
	IntfIPStr := strings.TrimPrefix(pdu.Name, OidIpNetToMediaPhysAddress+".")
	IntfIp := strings.SplitN(IntfIPStr, ".", 2)

	ifindex, err := strconv.Atoi(IntfIp[0])
	if err != nil {
		return err
	}
	if ifindex < 10000 {
		return nil
	}

	ip := IntfIp[1]
	macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	/*
		fmt.Printf("ifindex %d\n", ifindex)
		fmt.Printf("Ip %s\n", ip)
		fmt.Printf("MAC %s\n", macStr)
	*/

	var arpInfo *switchArp = new(switchArp)
	arpInfo.ip = ip
	arpInfo.mac = macStr
	arpInfo.ifindex = ifindex

	storeArpInfo2Map(ip, arpInfo)

	return nil
}

func getArpInfo(ipAddr string, readKey *string) {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return
	}
	defer params.Conn.Close()

	oid = OidIpNetToMediaPhysAddress
	err = params.Walk(oid, getArpInfoCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the arp table of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the arp table of ip(%s) fail", ipAddr)
	}
}

func getAllSwitchInfo() {

	/*
		for _, topoRe := range TopoRelationMap {
			printTopoRelation(topoRe)
			if topoRe.devType == SwitchL3Type || topoRe.devType == SwitchL2SnmpType {
				var edge *switchEdge = new(switchEdge)

				edge.ip = topoRe.devIp
				edge.readKey = topoRe.readKey

				storeSwitchEdge2Map(edge.ip, edge)
				logging.GetLogger().Debugf("find switchEdge ip:%s", edge.ip)
			}
			getFdbInfo(topoRe.devIp, &topoRe.readKey)

			if topoRe.devType == SwitchL3Type || topoRe.devType == RouteType {
				getArpInfo(topoRe.devIp, &topoRe.readKey)
			}
		}
	*/
}

func getBasePortCallback(pdu gosnmp.SnmpPDU) error {

	var ifindex int

	ifindex = pdu.Value.(int)
	portNum := len(basePort)

	basePort[portNum] = ifindex

	logging.GetLogger().Debugf("get port ifindex:%d, port num:%d\n", ifindex, portNum)

	return nil
}

func getBasePort(ipAddr string, readKey *string) {

	var oid string
	*readKey = confInfo.readKey

	params := &gosnmp.GoSNMP{
		Target:    ipAddr,
		Port:      confInfo.port,
		Community: *readKey,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}

	err := params.Connect()
	if err != nil {
		logging.GetLogger().Errorf("Connect() err: %v", err)
		return
	}
	defer params.Conn.Close()

	basePort = make([]int, 255)

	oid = OidBasePort
	err = params.Walk(oid, getBasePortCallback)
	if err == nil {
		logging.GetLogger().Debugf("get the base port of ip(%s) success", ipAddr)
	} else {
		logging.GetLogger().Debugf("get the base port of ip(%s) fail", ipAddr)
	}
}

/*
func getPortType() {
	for _, switchEdge := range edgeMap {
		getBasePort(switchEdge.ip, &switchEdge.readKey)
	}
}
*/

func getManIpFromLldpTable() {
	for _, deviceInfo := range deviceInfoMap {
		switchMac := deviceInfo.switchMac
		if ip, ok := switchMac2ManagementIp[switchMac]; ok {
			deviceInfo.managementIp = ip
		}
	}
}

func getSwitchEdge() {
	logging.GetLogger().Debug("------------begin count switch edge------------")

	getAllSwitchInfo()

	//getPortType()
}

/*
type snmpNode struct {
	id       graph.Identifier
	metadata graph.Metadata
	node     *graph.Node
	root     bool
	hostId   graph.Identifier
	name string
	ifindex int
	state string
	ifType string
}
*/

func printAllRelaTopo() {

	logging.GetLogger().Debugf("TopoRelationMap size: %d", len(TopoRelationMap))
	for _, topoRe := range TopoRelationMap {
		printTopoRelation(topoRe)
	}
}

func (s *SnmpProbe) createRootNode(deviceInfo *deviceInfo) *graph.Node {
	m := graph.Metadata{
		"Name":       deviceInfo.name,
		"Type":       "host",
		"Switch MAC": deviceInfo.switchMac,
		"IPV4":       deviceInfo.managementIp,
	}

	logging.GetLogger().Debugf("SNMP Root Node ADD name:%s boardSn:%s info %s", deviceInfo.name, deviceInfo.boardSn, deviceInfo.info)

	if root := s.Graph.GetNodes(m); root != nil {
		logging.GetLogger().Debugf("found root node %s in graph", deviceInfo.name)
		return root[0]
	}

	return s.Graph.NewNode(graph.GenID(), m, deviceInfo.info)
}

func (s *SnmpProbe) createNode(snmpNode *snmpNode, deviceInfo *deviceInfo) (*graph.Node, error) {

	var intf *graph.Node

	metadata := graph.Metadata{
		"Name":        snmpNode.name,
		"Description": snmpNode.description,
		"MTU":         1518,
		"Speed":       "10G/s",
		"State":       snmpNode.state,
		"Native Vlan": snmpNode.pVid,
	}

	if snmpNode.vlanName != "" {
		metadata["Vlan Interface"] = snmpNode.vlanName
		metadata["Vlan IP"] = snmpNode.vlanIp
		metadata["Vlan Mask"] = snmpNode.vlanMask
	}

	logging.GetLogger().Debugf("SNMP Node CHECK %s(%d,%s) within %s", snmpNode.name, snmpNode.ifindex, snmpNode.ifType, deviceInfo.rootNode.String())

	s.Graph.Lock()
	defer s.Graph.Unlock()

	//firstChild := s.Graph.LookupFirstChild(deviceInfo.rootNode, graph.Metadata{"Name": snmpNode.name, "IfIndex": snmpNode.ifindex})
	firstChild := s.Graph.LookupFirstChild(deviceInfo.rootNode, graph.Metadata{"Name": snmpNode.name})
	if firstChild != nil {
		logging.GetLogger().Debugf("find child node %s", snmpNode.name)
		return firstChild, nil
	}
	logging.GetLogger().Debugf("SNMP Node ADD %s(%d,%s) within %s", snmpNode.name, snmpNode.ifindex, snmpNode.ifType, deviceInfo.rootNode.String())

	intf = s.Graph.NewNode(graph.GenID(), metadata, deviceInfo.info)

	m := graph.Metadata{
		"Host": deviceInfo.name,
	}

	if !topology.HaveOwnershipLink(s.Graph, deviceInfo.rootNode, intf, nil) {
		logging.GetLogger().Debugf("snmp.AddOwnershipLink")
		topology.AddOwnershipLink(s.Graph, deviceInfo.rootNode, intf, m)
	}
	return intf, nil
}

func (s *SnmpProbe) createAllNode() {

	nodeMap = make(map[string]*snmpNode)

	for _, deviceInfo := range deviceInfoMap {
		logging.GetLogger().Errorf("create Node of device %s", deviceInfo.info)

		deviceInfo.rootNode = s.createRootNode(deviceInfo)
		deviceInfo.rootSnmpNode = new(snmpNode)
		deviceInfo.rootSnmpNode.node = deviceInfo.rootNode
		deviceInfo.rootSnmpNode.root = true
		deviceInfo.rootSnmpNode.id = deviceInfo.rootNode.ID
		nodeMap[deviceInfo.info] = deviceInfo.rootSnmpNode

		for _, lldpInfo := range deviceInfo.lldpMap {
			logging.GetLogger().Debugf("lldpInfo   ifindex %d", lldpInfo.ifindex)
			logging.GetLogger().Debugf("           localPort %s", lldpInfo.localPort)
			logging.GetLogger().Debugf("           remotePort %s", lldpInfo.remotePort)
			logging.GetLogger().Debugf("           chassisId %s", lldpInfo.chassisId)
			logging.GetLogger().Debugf("           manAddress %s", lldpInfo.manAddress)

			var node *snmpNode = new(snmpNode)
			node.name = lldpInfo.localPort
			node.ifindex = lldpInfo.ifindex
			node.state = "UP"
			node.info = deviceInfo.managementIp + ":" + lldpInfo.localPort

			node.description = deviceInfo.baseIntfMap[node.ifindex].description
			pVid := deviceInfo.baseIntfMap[node.ifindex].pVid
			state := deviceInfo.baseIntfMap[node.ifindex].state
			if state != "UP" {
				logging.GetLogger().Debugf("port %s is Down", node.name)
				continue
			}

			node.pVid = pVid
			node.vlanName = deviceInfo.vlanMap[pVid].name
			node.vlanIfindex = deviceInfo.vlanMap[pVid].ifindex
			node.vlanIp = deviceInfo.vlanMap[pVid].ip
			node.vlanMask = deviceInfo.vlanMap[pVid].mask
			node.vlanState = deviceInfo.vlanMap[pVid].state

			intfNode, err := s.createNode(node, deviceInfo)
			if err == nil {
				node.node = intfNode
				node.id = intfNode.ID
				nodeMap[node.info] = node
			}
		}
	}
}

func (s *SnmpProbe) deleteNodes() error {

	logging.GetLogger().Errorf("delete all the nodes which is not detected this time")

	for info, snmpNode := range oldNodeMap {
		if _, ok := nodeMap[info]; !ok {
			logging.GetLogger().Errorf("delete node: %v", snmpNode)
			if snmpNode.root {
				logging.GetLogger().Errorf("delete root node: %v", snmpNode)
				s.Graph.DelHostGraph(info)
			} else {
				s.Graph.DelNode(snmpNode.node)
			}
		}
	}

	oldNodeMap = nodeMap
	return nil
}

func (s *SnmpProbe) createEdge(edge *snmpEdge) error {
	logging.GetLogger().Debugf("s.createEdge info: %s", edge.info)
	from := edge.localAddress + ":" + edge.localPort
	fromNode, ok := nodeMap[from]
	if !ok {
		logging.GetLogger().Errorf("find from node of %s failed", from)
		return errors.New("no from node")
	}

	to := edge.remoteAddress + ":" + edge.remotePort
	toNode, ok := nodeMap[to]
	if !ok {
		logging.GetLogger().Errorf("find to node of %s failed", to)
		return errors.New("no to node")
	}

	m := graph.Metadata{}
	if !topology.HaveLayer2Link(s.Graph, fromNode.node, toNode.node, m) {
		logging.GetLogger().Debugf("snmp.AddLayer2Link")
		topology.AddLayer2Link(s.Graph, fromNode.node, toNode.node, m)
	} else {
		logging.GetLogger().Errorf("already has edge between %s and %s", from, to)
		return errors.New("already linked")
	}

	return nil
}

func (s *SnmpProbe) createAllEdge() {

	edgeMap = make(map[string]*snmpEdge)

	for _, deviceInfo := range deviceInfoMap {
		logging.GetLogger().Errorf("create Edge of device %s", deviceInfo.info)

		for _, lldpInfo := range deviceInfo.lldpMap {
			logging.GetLogger().Debugf("lldpInfo   ifindex %d", lldpInfo.ifindex)
			logging.GetLogger().Debugf("           localPort %s", lldpInfo.localPort)
			logging.GetLogger().Debugf("           remotePort %s", lldpInfo.remotePort)
			logging.GetLogger().Debugf("           chassisId %s", lldpInfo.chassisId)
			logging.GetLogger().Debugf("           manAddress %s", lldpInfo.manAddress)

			var edge *snmpEdge = new(snmpEdge)
			edge.localAddress = deviceInfo.managementIp
			edge.localPort = lldpInfo.localPort
			edge.remoteAddress = lldpInfo.manAddress
			edge.remotePort = lldpInfo.remotePort
			edge.info = edge.localAddress + ":" + edge.localPort + "-" + edge.remoteAddress + ":" + edge.remotePort

			//edgeCheck := edge.remoteAddress + edge.remotePort + edge.localAddress + edge.localPort

			//time.Sleep(time.Second * 2)
			err := s.createEdge(edge)
			if err == nil {
				edgeMap[edge.info] = edge
			}
		}
	}
}

func printAllEdge() {
	logging.GetLogger().Errorf("printAllEdge ...")
	for info, _ := range edgeMap {
		logging.GetLogger().Debugf("Edge info: %s", info)
	}
}
func (s *SnmpProbe) startScan() {
	logging.GetLogger().Debugf("snmp topo discover begin......")
	logging.GetLogger().Debugf("startScan IP %s, layer %d, period %d", confInfo.coreIp, confInfo.scanLayer, confInfo.period)

	deviceInfoMap = make(map[string]*deviceInfo)
	ipIntfAddrTableMap = make(map[string]*ipIntfAddrTable)

	logging.GetLogger().Debug("**************now scan 1 level info...")

	scanDeviceIp = confInfo.coreIp
	deviceScan(1, confInfo.coreIp)

	for scanLayer := 2; scanLayer <= confInfo.scanLayer; scanLayer++ {
		logging.GetLogger().Debugf("****************now scan %d level info...", scanLayer)
		scanLayerDevice(scanLayer)
	}

	//getManIpFromLldpTable()

	s.createAllNode()

	s.deleteNodes()

	s.createAllEdge()

	printAllDeviceInfo()
	printAllEdge()

	logging.GetLogger().Debugf("****************scan end")
	//getSwitchEdge()
}

func (s *SnmpProbe) detectTopology(detectInfo *TopologyDetect) {
	logging.GetLogger().Errorf("detectInfo IP %s, period %d, community %s", detectInfo.IP, detectInfo.Period, detectInfo.Community)

	confInfo.coreIp = detectInfo.IP
	confInfo.readKey = detectInfo.Community
	confInfo.period = int(detectInfo.Period)

	config := snmpConfig{}
	config.Detectip = confInfo.coreIp
	config.Detectperiod = confInfo.period
	config.Community = confInfo.readKey

	if config.Detectperiod == 0 {
		scanTicker.Stop()
		return
	}

	configJson, _ := json.Marshal(config)
	err := ioutil.WriteFile(DetectConfigFile, configJson, 0644)
	if err != nil {
		logging.GetLogger().Errorf("snmp write JSON file failed, err %s", err.Error())
		return
	}

	scanTicker = time.NewTicker(time.Duration(confInfo.period) * time.Minute)

	s.startScan()
}

func (s *SnmpProbe) Run() {
	time.Sleep(1 * time.Second)

	scanTicker = time.NewTicker(time.Duration(confInfo.period) * time.Minute)
	defer scanTicker.Stop()

	oldNodeMap = make(map[string]*snmpNode)

	s.startScan()

	atomic.StoreInt64(&s.state, common.RunningState)
	for atomic.LoadInt64(&s.state) == common.RunningState {
		select {
		case <-scanTicker.C:
			s.startScan()
		case detectInfo := <-TopologyDetectChan:
			s.detectTopology(detectInfo)
		}
	}
}

func (s *SnmpProbe) Start() {
	logging.GetLogger().Debug("(u *SnmpProbe) start()")
	TopologyDetectChan = make(chan *TopologyDetect, 10)
	go s.Run()
	logging.GetLogger().Debug("snmp topo discover after goroutinue......")
}

func (s *SnmpProbe) Stop() {
}

func InitSnmpConfig() error {

	raw, err := ioutil.ReadFile(DetectConfigFile)
	if err != nil {
		logging.GetLogger().Errorf("snmp read JSON file failed, err %s", err.Error())
		return err
	}
	config := snmpConfig{}
	err = json.Unmarshal([]byte(raw), &config)
	if err != nil {
		logging.GetLogger().Debug("snmp Unmarshal JSON file failed, err %s", err.Error())
		return err
	}
	logging.GetLogger().Errorf("InitSnmpConfig config %v", config)
	logging.GetLogger().Errorf("InitSnmpConfig IP %s, period %d community %s", config.Detectip, config.Detectperiod, config.Community)

	if ip := net.ParseIP(config.Detectip); ip == nil {
		logging.GetLogger().Errorf("InitSnmpConfig get wrong ip address")
		return errors.New("wrong IP address")
	}

	confInfo.coreIp = config.Detectip

	if config.Detectperiod <= 0 {
		config.Detectperiod = 10
	}
	confInfo.period = config.Detectperiod

	if len(config.Community) == 0 {
		config.Community = "public"
	}
	confInfo.readKey = config.Community

	return nil
}

func NewSnmpProbeFromConfig(g *graph.Graph) *SnmpProbe {
	/*
		detectip := config.GetConfig().GetString("agent.topology.snmpdetectip")
		detectperiod := config.GetConfig().GetString("agent.topology.snmpdetectperiod")
		detectlayer := config.GetConfig().GetString("agent.topology.snmpdetectlayer")
		community := config.GetConfig().GetString("agent.topology.snmpdetectcommunity")

		confInfo.coreIp = detectip
		layer, err := strconv.Atoi(detectlayer)
		if err != nil {
			layer = 10
		}
		confInfo.scanLayer = layer

		period, err := strconv.Atoi(detectperiod)
		if err != nil {
			period = 10
		}

		confInfo.period = period

		confInfo.readKey = community
	*/

	InitSnmpConfig()

	return &SnmpProbe{
		Graph: g,
	}
}
