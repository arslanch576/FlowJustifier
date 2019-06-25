#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel
from functools import partial
import time
import os
import random
import threading
import os


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."

    def build(self, n=3, m=2, a=4):
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)
        for h in range(m):
            host = self.addHost('m%s' % (h + 1))
            self.addLink(host, switch)
        for h in range(a):
            host = self.addHost('a%s' % (h + 1))
            self.addLink(host, switch)


class NormalRequestSenderThread(threading.Thread):
    def __init__(self, net, globalValues):
        threading.Thread.__init__(self)
        self.name = "Normal requests sender thread"
        self.net = net
        self.globalValues = globalValues
        self.sleepTime = float(
            float(self.globalValues["timeSlotDuratoin"]) / float(self.globalValues["normalRequestsPerTimeSlot"]))

    def run(self):
        print("Starting " + self.name)
        serverNodeIp = self.net.get("h1").IP()
        while (1):
            if (self.globalValues["moreToSend_normal"] <= 0):
                try:
                    time.sleep(self.sleepTime - 0.06)
                except:
		    None
                continue
            senderHost = self.net.get("h%s" % random.randint(1, self.globalValues["totalNormalNodes"]))
            try:
                print(senderHost.cmd('python myClient.py -i %s -m "h"' % serverNodeIp))
            except:
                continue
            self.globalValues["moreToSend_normal"] = self.globalValues["moreToSend_normal"] - 1
            self.globalValues["totalNormalRequestsSent"] = self.globalValues["totalNormalRequestsSent"] + 1
            self.globalValues["normalRequestsSentThisTimeSlot"] = self.globalValues[
                                                                      "normalRequestsSentThisTimeSlot"] + 1
	    try:
                time.sleep(self.sleepTime - 0.20)
            except:
		None


class AttackerRequestSenderThread(threading.Thread):
    def __init__(self, net, globalValues):
        threading.Thread.__init__(self)
        self.name = "Attacker requests sender thread"
        self.net = net
        self.globalValues = globalValues

    def run(self):
        print("Starting " + self.name)
        serverNodeIp = self.net.get("h1").IP()
        while (1):
            self.sleepTime = float(
                float(self.globalValues["timeSlotDuratoin"]) / float(self.globalValues["attackerRequestsPerTimeSlot"]))
            if (self.globalValues["moreToSend_attacker"] <= 0):
                try:
                    time.sleep(self.sleepTime - 0.06)
                except:
		    None
                continue
            senderHost = self.net.get("a%s" % random.randint(1, self.globalValues["totalAttackerNodes"]))
            try:
                print(senderHost.cmd('python myClient.py -i %s -m "h"' % serverNodeIp))
            except:
                continue
            self.globalValues["moreToSend_attacker"] = self.globalValues["moreToSend_attacker"] - 1
            self.globalValues["totalAttackerRequestsSent"] = self.globalValues["totalAttackerRequestsSent"] + 1
            self.globalValues["attackerRequestsSentThisTimeSlot"] = self.globalValues[
                                                                        "attackerRequestsSentThisTimeSlot"] + 1
            try:
                time.sleep(self.sleepTime - 0.22)
            except:
		None


class DisplayManager(threading.Thread):
    def __init__(self, globalValues):
        threading.Thread.__init__(self)
        self.name = "DisplayManager"
        self.globalValues = globalValues

    def run(self):
        print("Starting " + self.name)
        while (1):
            os.system('clear')
            print("Current Time Slot : %d" % (self.globalValues["currentTimeSlot"]))
            print("Normal requests send in this timeslot: %d" % (self.globalValues["normalRequestsSentThisTimeSlot"]))
            print(
                "Attacker requests send in this timeslot: %d" % (self.globalValues["attackerRequestsSentThisTimeSlot"]))
            print("Total requests send in this timeslot: %d" % (
                    self.globalValues["normalRequestsSentThisTimeSlot"] + self.globalValues[
                "attackerRequestsSentThisTimeSlot"]))
            print("\n")
            print("Total Normal requests sent: %d" % (self.globalValues["totalNormalRequestsSent"]))
            print("Total Attacker requests sent: %d" % (self.globalValues["totalAttackerRequestsSent"]))
            print("Total requests sent: %d" % (
                    self.globalValues["totalNormalRequestsSent"] + self.globalValues["totalAttackerRequestsSent"]))

            time.sleep(0.5)


class TimeSlotTrigger(threading.Thread):
    def __init__(self, globalValues):
        threading.Thread.__init__(self)
        self.name = "TimeSlotTrigger"
        self.globalValues = globalValues

    def run(self):
        print("Starting " + self.name)
        while (1):
            time.sleep(self.globalValues["timeSlotDuratoin"])
            self.globalValues["currentTimeSlot"] = self.globalValues["currentTimeSlot"] + 1
            self.globalValues["normalRequestsSentThisTimeSlot"] = 0
            self.globalValues["attackerRequestsSentThisTimeSlot"] = 0
            self.globalValues["moreToSend_normal"] = self.globalValues["normalRequestsPerTimeSlot"]
            self.globalValues["attackerRequestsPerTimeSlot"] = self.globalValues["attackerRequestsPerTimeSlot"] + 2
            self.globalValues["moreToSend_attacker"] = self.globalValues["attackerRequestsPerTimeSlot"]


if __name__ == '__main__':
    setLogLevel('info')
    os.system('clear')

    globalValus = {}
    globalValus["timeSlotDuratoin"] = 20
    globalValus["normalRequestsPerTimeSlot"] = 112
    globalValus["attackerRequestsPerTimeSlot"] = 56
    globalValus["moreToSend_attacker"] = globalValus["attackerRequestsPerTimeSlot"]
    globalValus["moreToSend_normal"] = globalValus["normalRequestsPerTimeSlot"]
    globalValus["totalNormalNodes"] = 100
    globalValus["totalAttackerNodes"] = 100
    globalValus["totalInactiveNodes"] = 0

    globalValus["currentTimeSlot"] = 1
    globalValus["totalNormalRequestsSent"] = 0
    globalValus["totalAttackerRequestsSent"] = 0
    globalValus["normalRequestsSentThisTimeSlot"] = 0
    globalValus["attackerRequestsSentThisTimeSlot"] = 0

    mytopo = SingleSwitchTopo(globalValus["totalNormalNodes"], globalValus["totalInactiveNodes"],
                              globalValus["totalAttackerNodes"])
    net = Mininet(topo=mytopo, controller=partial(RemoteController, ip='127.0.0.1', port=6633))
    net.start()

    for i in range(globalValus["totalNormalNodes"]):
        host = net.get("h%d" % (i + 1))
        host.setIP("10.0.0.%d" % (i + 1))
        print("MAC=%s | IP=%s" % (host.MAC(), host.IP()))

    for i in range(globalValus["totalAttackerNodes"]):
        host = net.get("a%d" % (i + 1))
        host.setIP("10.1.0.%d" % (i + 1))
        print("MAC=%s | IP=%s" % (host.MAC(), host.IP()))

    for i in range(globalValus["totalInactiveNodes"]):
        host = net.get("m%d" % (i + 1))
        host.setIP("10.2.0.%d" % (i + 1))
        print("MAC=%s | IP=%s" % (host.MAC(), host.IP()))

    h1 = net.get("h1")
    p1 = h1.popen('python myServer.py -i %s &' % h1.IP())

    thread_normal_requests_sender = NormalRequestSenderThread(net, globalValus)
    thread_normal_requests_sender.start()

    thread_attacker_requests_sender = AttackerRequestSenderThread(net, globalValus)
    thread_attacker_requests_sender.start()

    thread_display = DisplayManager(globalValus)
    thread_display.start()

    thread_time_slot_trigger = TimeSlotTrigger(globalValus)
    thread_time_slot_trigger.start()
