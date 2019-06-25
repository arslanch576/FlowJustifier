from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import os
import time
import threading

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0


class Scheduling(threading.Thread):

    def __init__(self, threadID, connection, transparent, hold_down_expired, macToPort, event_list, queue1, queue2,
                 queue3,queue4,queue5, globalValues):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.connection = connection
        self.transparent = transparent
        self.hold_down_expired = hold_down_expired
        self.macToPort = {}
        self.trustValueList = {}
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.queue4 = queue4
        self.queue5 = queue5

        self.globalValues = globalValues

        load_trust_values_from_file(self, "file1.txt", self.trustValueList)
        self.event_list = event_list
        log.debug("Scheduling thread launched")

    def run(self):
        queues = list()
        queues.append(self.queue1)
        queues.append(self.queue2)
        queues.append(self.queue3)
        queues.append(self.queue4)
        queues.append(self.queue5)
        w = list()
        while 1:
            w = list()
            w.append(int(round(float(len(self.queue1)) / float(max(len(self.queue1), 1)) * 2)))
            w.append(int(round(float(len(self.queue2)) / float(max(len(self.queue1), 1)) * 4)))
            w.append(int(round(float(len(self.queue3)) / float(max(len(self.queue1), 1)) * 6)))
            w.append(int(round(float(len(self.queue4)) / float(max(len(self.queue1), 1)) * 8)))
            w.append(int(round(float(len(self.queue5)) / float(max(len(self.queue1), 1)) * 10)))
            i = -1;
            for value in w:
                # print("from %d requests %d will be poped" % (i + 1, value))
                i = i + 1
                for x in range(value):
                    if (queues[i].__len__() > 0):
                        if self.globalValues["moreToProcess"] > 0:
                            sleepTime = float(float(self.globalValues["timeSlotDuration"]) / float(
                                self.globalValues["requestsPerTimeSlot"]))
                            event = queues[i].pop()
                            self.globalValues["totalProcessed"] = self.globalValues["totalProcessed"] + 1
                            if (i == 0):
                                self.globalValues["processedQ1"] = self.globalValues["processedQ1"] + 1
                            if (i == 1):
                                self.globalValues["processedQ2"] = self.globalValues["processedQ2"] + 1
                            if (i == 2):
                                self.globalValues["processedQ3"] = self.globalValues["processedQ3"] + 1
                            if (i == 3):
                                self.globalValues["processedQ4"] = self.globalValues["processedQ4"] + 1
                            if (i == 4):
                                self.globalValues["processedQ5"] = self.globalValues["processedQ5"] + 1
                            self.globalValues["moreToProcess"] = self.globalValues["moreToProcess"] - 1
                            # print("processing: from queue: %d" % (i))
                            # while 1:
                            #     if len(self.event_list)>0:
                            #         event=self.event_list.pop()
                            #         log.debug("new event found %d" % (len(self.event_list),))
                            #     else:
                            #         save_trust_values_in_file(self,"file1.txt",self.trustValueList)
                            #         time.sleep(1)
                            #         continue;
                            packet = event.parsed

                            self.macToPort[packet.src] = event.port  # 1

                            if not self.transparent:  # 2
                                if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                                    drop(self, event)  # 2a
                                    return

                            # if packet.dst.is_multicast:
                            #    log.debug("flooded due to multicast")
                            #    flood(self, event)
                            # drop(self,event,100) # 3a
                            # else:
                            if packet.dst not in self.macToPort:  # 4

                                if packet.next.protosrc.__str__()[:4] == ("10.0"):
                                    self.globalValues["normalRequestsProcessed"] = self.globalValues[
                                                                                       "normalRequestsProcessed"] + 1

                                if packet.next.protosrc.__str__()[:4] == ("10.1"):
                                    self.globalValues["attackerRequestsProcessed"] = self.globalValues[
                                                                                         "attackerRequestsProcessed"] + 1
                                drop(self, event)
                                time.sleep(sleepTime - 0.10)
                                # log.debug("droped")
                                # flood(self, event, "Port for %s unknown -- flooding" % (packet.dst,))  # 4a
                            else:
                                port = self.macToPort[packet.dst]
                                if port == event.port:  # 5
                                    # 5a
                                    log.debug("Same port for packet from %s -> %s on %s.%s.  Drop."
                                              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                                    drop(self, event, 10)
                                    return
                                # 6
                                log.debug("installing flow for %s.%i -> %s.%i" %
                                          (packet.src, event.port, packet.dst, port))
                                msg = of.ofp_flow_mod()
                                msg.match = of.ofp_match.from_packet(packet, event.port)
                                msg.idle_timeout = 10
                                msg.hard_timeout = 30
                                msg.actions.append(of.ofp_action_output(port=port))
                                msg.data = event.ofp  # 6a
                                self.connection.send(msg)
                        else:
                            time.sleep(0.2)


def addInQueue(self, event, trustValue, queue1, queue2, queue3,queue4,queue5, globalValues):
    i = ((trustValue - globalValues["trustValueMin"]) * 5.0) / float((
            globalValues["trustValueMax"] - globalValues["trustValueMin"]))

    # print("Trust value: %d, Queue: %f" % (trustValue, i))

    i = round(i)
    if (len(queue1) + len(queue2) + len(queue3)+ len(queue4)+ len(queue5)) < 100:
        if i == 0:
            queue1.insert(0, event)
        elif i == 1:
            queue2.insert(0, event)
        elif i == 2:
            queue3.insert(0, event)
        elif i == 3:
            queue4.insert(0, event)
        else:
            queue5.insert(0, event)
    elif i == 0:
        self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
        drop(self, event)
        anotherRequestRejected(event.parsed, self)
    else:
        if len(queue1) > 0:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            e = queue1.pop(0)
            drop(self, e)
            anotherRequestRejected(e.parsed, self)
            if i == 0:
                queue1.insert(0, event)
            elif i == 1:
                queue2.insert(0, event)
            elif i == 2:
                queue3.insert(0, event)
            elif i == 3:
                queue4.insert(0, event)
            else:
                queue5.insert(0, event)
        elif len(queue2) > 0:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            e = queue2.pop(0)
            drop(self, e)
            anotherRequestRejected(e.parsed, self)
            if i == 0:
                queue1.insert(0, event)
            elif i == 1:
                queue2.insert(0, event)
            elif i == 2:
                queue3.insert(0, event)
            elif i == 3:
                queue4.insert(0, event)
            else:
                queue5.insert(0, event)
        elif len(queue3) > 0:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            e = queue3.pop(0)
            drop(self, e)
            anotherRequestRejected(e.parsed, self)
            if i == 0:
                queue1.insert(0, event)
            elif i == 1:
                queue2.insert(0, event)
            elif i == 2:
                queue3.insert(0, event)
            elif i == 3:
                queue4.insert(0, event)
            else:
                queue5.insert(0, event)
        elif len(queue4) > 0:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            e = queue4.pop(0)
            drop(self, e)
            anotherRequestRejected(e.parsed, self)
            if i == 0:
                queue1.insert(0, event)
            elif i == 1:
                queue2.insert(0, event)
            elif i == 2:
                queue3.insert(0, event)
            elif i == 3:
                queue4.insert(0, event)
            else:
                queue5.insert(0, event)
        elif len(queue5) > 0:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            e = queue5.pop(0)
            drop(self, e)
            anotherRequestRejected(e.parsed, self)
            if i == 0:
                queue1.insert(0, event)
            elif i == 1:
                queue2.insert(0, event)
            elif i == 2:
                queue3.insert(0, event)
            elif i == 3:
                queue4.insert(0, event)
            else:
                queue5.insert(0, event)
        else:
            self.globalValues["dropLessSpaceInQueue"] = self.globalValues["dropLessSpaceInQueue"] + 1
            drop(self, event)
            anotherRequestRejected(event.parsed, self)


def load_trust_values_from_file(self, file, dickt):
    self.trustValueList.clear()
    file = open(file, "r")
    lines = file.readlines()
    print(lines.__len__())
    for line in lines:
        key, value = line.split(",")
        value = int(value, 10)
        self.trustValueList[key] = value
    calculateMaxMinTrustValue(self)
    file.close()


def calculateMaxMinTrustValue(self):
    self.globalValues["trustValueMax"]=0
    self.globalValues["trustValueMin"]=10000
    for key, value in self.trustValueList.items():
        if value > self.globalValues["trustValueMax"]:
            self.globalValues["trustValueMax"] = value

        if value < self.globalValues["trustValueMin"]:
            self.globalValues["trustValueMin"] = value


def save_trust_values_in_file(self, file, dickt):
    file = open(file, "w")
    for key, value in self.trustValueList.items():
        file.write(key + "," + value.__str__() + "\n")


def save_abnormal_threshold_values_in_file(self, file, dickt):
    file = open(file, "w")
    for key, value in self.abnormalThresholdList.items():
        file.write(key + "," + value.__str__() + "\n")


def load_abnormal_threshold_values_from_file(self, file):
    self.abnormalThresholdList.clear()
    file = open(file, "r")
    lines = file.readlines()
    print(lines.__len__())
    for line in lines:
        key, value = line.split(",")
        value = int(value, 10)
        self.abnormalThresholdList[key] = value

        # print(self.trustValueList[key])
    file.close()


def save_in_dict(self, file, ip, port, trust_value):
    file = open(file, "a+")
    self.trustValueList[ip + ":" + port.__str__()] = trust_value
    file.write(ip + ":" + port.__str__())
    file.write("," + trust_value.__str__() + "\n")
    file.close()


def blackListUser(self, event, key):
    self.blackList[key]=1


def controlerUnderAttack(self):
    if (len(self.queue1) + len(self.queue2) + len(self.queue3) + len(self.queue4) + len(self.queue5)) > int(self.globalValues["requestsPerTimeSlot"]*0.9):
        return True
    else:
        return False


def anotherRequestRejected(packet, self):
    if packet.next.protosrc.__str__()[:4] == ("10.0"):
        self.globalValues["normalRequestsRejected"] = self.globalValues["normalRequestsRejected"] + 1

    if packet.next.protosrc.__str__()[:4] == ("10.1"):
        self.globalValues["attackerRequestsRejected"] = self.globalValues[
                                                            "attackerRequestsRejected"] + 1


def drop(self, event, duration=None):
    """
    Drops this packet and optionally installs a flow to continue
    dropping similar ones for a while
    """
    packet = event.parsed
    if duration is not None:
        if not isinstance(duration, tuple):
            duration = (duration, duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
    elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)


class LearningSwitch(object):

    def __init__(self, connection, transparent):
        log.debug("starting")
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent

        # We just use this to know when to log a helpful message
        self.hold_down_expired = _flood_delay == 0
        # Our table
        self.macToPort = {}
        self.event_list = list()
        self.trustValueList = {}
        self.abnormalThresholdList = {}
        self.blackList = {}

        self.queue1 = list()
        self.queue2 = list()
        self.queue3 = list()
        self.queue4 = list()
        self.queue5 = list()

        self.thisTimeSlot = {}

        self.globalValues = {}
        self.globalValues["requestsPerTimeSlot"] = 100
        self.globalValues["expectedRequestsThisTimeSlot"] = 150
        self.globalValues["moreToProcess"] = 100
        self.globalValues["trustValueMininum"] = 1
        self.globalValues["trustValueMininumForList"] = 0
        self.globalValues["dropAbnormalThreshold"] = 0
        self.globalValues["dropLessTrustValue"] = 0
        self.globalValues["dropBlackListed"] = 0
        self.globalValues["dropLessSpaceInQueue"] = 0
        self.globalValues["timeSlot"] = 1
        self.globalValues["timeSlotDuration"] = 30
        self.globalValues["trustValueMax"] = 2
        self.globalValues["trustValueMin"] = 1
        self.globalValues["totalProcessed"] = 0
        self.globalValues["processedQ1"] = 0
        self.globalValues["processedQ2"] = 0
        self.globalValues["processedQ3"] = 0
        self.globalValues["processedQ4"] = 0
        self.globalValues["processedQ5"] = 0
        self.globalValues["normalBlocked"] = 0
        self.globalValues["attackerBlocked"] = 0
        self.globalValues["normalRequestsRecieved"] = 0
        self.globalValues["normalRequestsRejected"] = 0
        self.globalValues["attackerRequestsRecieved"] = 0
        self.globalValues["attackerRequestsRejected"] = 0
        self.globalValues["normalRequestsProcessed"] = 0
        self.globalValues["attackerRequestsProcessed"] = 0

        load_abnormal_threshold_values_from_file(self, "file2.txt")

        self.thread_queuing = TrustAndQueuingManagment(self.event_list, self.connection, self.queue1, self.queue2,
                                                       self.queue3,self.queue4,self.queue5,
                                                       self.trustValueList, self.abnormalThresholdList,
                                                       self.thisTimeSlot, self.globalValues, self.blackList)
        self.thread_queuing.start()
        self.thread_scheduaing = Scheduling(1, self.connection, self.transparent, self.hold_down_expired,
                                            self.macToPort,
                                            self.event_list, self.queue1, self.queue2, self.queue3,self.queue4,self.queue5, self.globalValues)
        self.thread_scheduaing.start()

        self.thread_timeslottrigger = TimeSlotTrigger(self.event_list, self.queue1, self.queue2, self.queue3,self.queue4,self.queue5,
                                                      self.trustValueList, self.abnormalThresholdList,
                                                      self.thisTimeSlot, self.globalValues)
        self.thread_timeslottrigger.start()

        self.thread_display = DisplayManager(self.event_list, self.queue1, self.queue2, self.queue3,self.queue4,self.queue5,
                                             self.trustValueList, self.thisTimeSlot, self.globalValues)
        self.thread_display.start()

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        # log.debug("Initializing LearningSwitch, transparent=%s",
        #          str(self.transparent))

    def _handle_PacketIn(self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        self.event_list.insert(0, event)
        # log.debug("new event added %d" % (len(self.event_list),))


class DisplayManager(threading.Thread):
    def __init__(self, event_list, queue1, queue2, queue3,queue4,queue5, trustValueList, thisTimeSlot, globalValues):
        threading.Thread.__init__(self)
        self.name = "DisplayManager"
        self.event_list = event_list
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.queue4 = queue4
        self.queue5 = queue5
        self.trustValueList = trustValueList
        self.thisTimeSlot = thisTimeSlot
        self.globalValues = globalValues
        load_trust_values_from_file(self, "file1.txt", self.trustValueList)
        self.event_list = event_list
        log.debug("DisplayManager thread launched")

    def run(self):
        print("Starting " + self.name)
        while (1):
            os.system('clear')
            print("Current Time Slot : %d" % (self.globalValues["timeSlot"]))
            print("Requests processed in this time slot : %d" % (len(self.thisTimeSlot) / 2))
            print("Requests processed from Queue 1 : %d" % (self.globalValues["processedQ1"]))
            print("Requests processed from Queue 2 : %d" % (self.globalValues["processedQ2"]))
            print("Requests processed from Queue 3 : %d" % (self.globalValues["processedQ3"]))
            print("Requests processed from Queue 4 : %d" % (self.globalValues["processedQ4"]))
            print("Requests processed from Queue 5 : %d" % (self.globalValues["processedQ5"]))

            print("Normal requests recieved : %d" % (self.globalValues["normalRequestsRecieved"]))
            print("Attacker requests recieved : %d" % (self.globalValues["attackerRequestsRecieved"]))
            print("Total requests recieved : %d" % (
                    self.globalValues["attackerRequestsRecieved"] + self.globalValues["normalRequestsRecieved"]))

            print("Normal requests Processed : %d" % (self.globalValues["normalRequestsProcessed"]))
            print("Attacker requests Processed : %d" % (self.globalValues["attackerRequestsProcessed"]))
            print("Total Requests processed : %d" % (self.globalValues["totalProcessed"]))

            print("Normal requests rejected : %d" % (self.globalValues["normalRequestsRejected"]))
            print("Attackers requests rejected : %d" % (self.globalValues["attackerRequestsRejected"]))


            print("Normal blocked : %d" % (self.globalValues["normalBlocked"]))
            print("Attackers blocked : %d" % (self.globalValues["attackerBlocked"]))

            print("dropped due to abnormal threshold  : %d" % (self.globalValues["dropAbnormalThreshold"]))
            print("dropped due to less trust value : %d" % (self.globalValues["dropLessTrustValue"]))
            print("dropped because blacklisted : %d" % (self.globalValues["dropBlackListed"]))
            print("dropped due to no space in queue : %d" % (self.globalValues["dropLessSpaceInQueue"]))
            print("total dropped : %d" % (
                    self.globalValues["dropLessSpaceInQueue"] + self.globalValues["dropLessTrustValue"] +
                    self.globalValues["dropAbnormalThreshold"] + self.globalValues["dropBlackListed"]))

            print("Unprocessed Events: %d" % (len(self.event_list)))
            print("Requests in queue 1 : %d" % (len(self.queue1)))
            print("Requests in queue 2 : %d" % (len(self.queue2)))
            print("Requests in queue 3 : %d" % (len(self.queue3)))
            print("Requests in queue 4 : %d" % (len(self.queue4)))
            print("Requests in queue 5 : %d" % (len(self.queue5)))
            print("Length of trust value list : %d" % (len(self.trustValueList)))
            print("Maximum trust value : %d" % (self.globalValues["trustValueMax"]))
            print("Mininum trust value : %d" % (self.globalValues["trustValueMin"]))

            print("thisTimeSlot list : %d" % (len(self.thisTimeSlot)))

            time.sleep(0.5)


class TimeSlotTrigger(threading.Thread):
    def __init__(self, event_list, queue1, queue2, queue3,queue4,queue5, trustValueList, abnormalThresholdList, thisTimeSlot,
                 globalValues):
        threading.Thread.__init__(self)
        self.name = "TimeSlotTrigger"
        self.event_list = event_list
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.queue4 = queue4
        self.queue5 = queue5
        self.trustValueList = trustValueList
        self.abnormalThresholdList = abnormalThresholdList
        self.thisTimeSlot = thisTimeSlot
        self.globalValues = globalValues
        load_trust_values_from_file(self, "file1.txt", self.trustValueList)
        self.event_list = event_list
        log.debug("TimeSlotTrigger thread launched")

    def run(self):
        print("Starting " + self.name)
        while (1):
            time.sleep(self.globalValues["timeSlotDuration"])
            for key, value in self.trustValueList.items():
                if (key not in self.thisTimeSlot):
                    self.trustValueList[key] = int(round(self.trustValueList[key] * 0.9))
                    if self.trustValueList[key] < self.globalValues["trustValueMininum"]:
                        self.trustValueList.pop(key,None)
                else:
                    if self.thisTimeSlot[key]>self.abnormalThresholdList[key]:
                        self.abnormalThresholdList[key]=self.thisTimeSlot[key]
                    # self.abnormalThresholdList[key] = self.abnormalThresholdList[key] + int(
                    #     round((self.thisTimeSlot[key] - self.abnormalThresholdList[key]) * 0.5))
            calculateMaxMinTrustValue(self)
            self.thisTimeSlot.clear()
            self.globalValues["timeSlot"] = self.globalValues["timeSlot"] + 1
            self.globalValues["moreToProcess"] = self.globalValues["moreToProcess"] + self.globalValues[
                "requestsPerTimeSlot"]
            self.globalValues["expectedRequestsThisTimeSlot"] = self.globalValues["expectedRequestsThisTimeSlot"] + 2


class TrustAndQueuingManagment(threading.Thread):
    def __init__(self, event_list, connection, queue1, queue2, queue3,queue4,queue5, trustValueList, abnormalThresholdList,
                 thisTimeSlot,
                 globalValues,blackList):
        threading.Thread.__init__(self)
        self.name = "queueing managment"
        self.event_list = event_list
        self.connection = connection
        self.queue1 = queue1
        self.queue2 = queue2
        self.queue3 = queue3
        self.queue4 = queue4
        self.queue5 = queue5
        self.trustValueList = trustValueList
        self.abnormalThresholdList = abnormalThresholdList
        self.blackList=blackList
        self.thisTimeSlot = thisTimeSlot
        self.globalValues = globalValues
        load_trust_values_from_file(self, "file1.txt", self.trustValueList)
        self.event_list = event_list
        log.debug("TrustAndQueuingManagment thread launched")

    def run(self):
        print("Starting " + self.name)
        count = 0
        while 1:

            if len(self.event_list) > 0:
                event = self.event_list.pop()
                droped = False
                packet = event.parsed
                # print("new event found %d" % (len(self.event_list)))
                key = packet.next.protosrc.__str__() + ":" + event.port.__str__()
                timeslotKey = packet.next.protosrc.__str__() + ":" + event.port.__str__() + "->" + packet.dst.__str__()

                if timeslotKey in self.thisTimeSlot:
                    self.thisTimeSlot[timeslotKey] = self.thisTimeSlot[timeslotKey] + 1
                else:
                    self.thisTimeSlot[timeslotKey] = 1

                if self.thisTimeSlot[timeslotKey] % 3 != 1:
                    # print("Skipped  " + timeslotKey)
                    drop(self, event)
                    droped = True
                    None
                elif key in self.blackList:
		    if packet.next.protosrc.__str__()[:4] == ("10.0"):
                        self.globalValues["normalRequestsRecieved"] = self.globalValues["normalRequestsRecieved"] + 1

                    if packet.next.protosrc.__str__()[:4] == ("10.1"):
                        self.globalValues["attackerRequestsRecieved"] = self.globalValues[
                                                                            "attackerRequestsRecieved"] + 1

                    self.globalValues["dropBlackListed"] = self.globalValues["dropBlackListed"] + 1
		    anotherRequestRejected(packet, self)
		    #self.globalValues["moreToProcess"] = self.globalValues["moreToProcess"] - 1
		    droped = True
                    drop(self,event)
                else:
                    if packet.next.protosrc.__str__()[:4] == ("10.0"):
                        self.globalValues["normalRequestsRecieved"] = self.globalValues["normalRequestsRecieved"] + 1

                    if packet.next.protosrc.__str__()[:4] == ("10.1"):
                        self.globalValues["attackerRequestsRecieved"] = self.globalValues[
                                                                            "attackerRequestsRecieved"] + 1

                    if key in self.thisTimeSlot:
                        self.thisTimeSlot[key] = self.thisTimeSlot[key] + 1
                    else:
                        self.thisTimeSlot[key] = 1

                    if key not in self.trustValueList:
                        self.trustValueList[key] = 1
                        self.abnormalThresholdList[key] = 3
                    else:
                        if self.thisTimeSlot[key] > self.abnormalThresholdList[key]:
                            drop(self, event)
                            self.globalValues["dropAbnormalThreshold"] = self.globalValues["dropAbnormalThreshold"] + 1
                            anotherRequestRejected(packet, self)
                            droped = True
                        else:
                            if controlerUnderAttack(self):
                                self.trustValueList[key] = self.trustValueList[key] - 1
                            else:
                                self.trustValueList[key] = self.trustValueList[key] + 1

                            calculateMaxMinTrustValue(self)

                        if (self.trustValueList[key] < self.globalValues["trustValueMininum"]):
                            drop(self, event)
                            blackListUser(self,event,key)
			    if packet.next.protosrc.__str__()[:4] == ("10.0"):
                        	self.globalValues["normalBlocked"] = self.globalValues["normalBlocked"] + 1
			    else:
                        	self.globalValues["attackerBlocked"] = self.globalValues["attackerBlocked"] + 1
                            self.globalValues["dropLessTrustValue"] = self.globalValues["dropLessTrustValue"] + 1
                            anotherRequestRejected(packet, self)
                            droped = True
                    if droped == False:
                        addInQueue(self, event, self.trustValueList[key], self.queue1, self.queue2, self.queue3,self.queue4,self.queue5,
                                   self.globalValues)

            else:
                save_trust_values_in_file(self, "file1.txt", self.trustValueList)
                save_abnormal_threshold_values_in_file(self, "file2.txt", self.abnormalThresholdList)
                time.sleep(0.3)
                continue;
        print("Exiting " + self.name)
        print("%s \n\n %s \n\n %s \n\n " % (self.queue1.__str__(), self.queue2.__str__(), self.queue3.__str__(),))
        print("Schedualing")


class l2_learning(object):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """

    def __init__(self, transparent):
        core.openflow.addListeners(self)
        self.transparent = transparent

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent)
        log.debug("started LearningSwitch")


def launch(transparent=False, hold_down=_flood_delay):
    """
    Starts an L2 learning switch.
    """
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    core.registerNew(l2_learning, str_to_bool(transparent))
