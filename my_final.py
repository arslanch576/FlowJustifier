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

    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.parent = parent
        load_trust_values_from_file(parent, "after50Me.txt")
        log.debug("Scheduling thread launched")

    def run(self):
        while 1:
            w = list()
            f = 2
            for queue in self.parent.queues:
                w.append(int(round(float(len(queue)) / float(max(len(self.parent.queues[0]), 1)) * (f))))
                f = f + 2
            i = -1;
            for value in w:
                # print("from %d requests %d will be poped" % (i + 1, value))
                i = i + 1
                for x in range(value):
                    if (self.parent.queues[i].__len__() > 0):
                        if self.parent.moreRequestsToProcess > 0:
                            event = self.parent.queues[i].pop()
                            self.parent.totalRequestsProcessed = self.parent.totalRequestsProcessed + 1
                            self.parent.processedFromQueue[i] = self.parent.processedFromQueue[i] + 1
                            self.parent.moreRequestsToProcess = self.parent.moreRequestsToProcess - 1

                            process(self, event)

                    else:
                        #time.sleep(0.2)
			None


def findLength(queues):
    length = 0;
    for queue in queues:
        length = length + len(queue)
    return length


def addInQueue(self, event, trustValue):
    i = ((trustValue - self.parent.trustValueMin) * float(self.parent.NUM_QUEUES)) / float((
            self.parent.trustValueMax - self.parent.trustValueMin))
    #print("i=%d" % (i))
    # print("Trust value: %d, Queue: %f" % (self.parent.trustValue, i))
    packet = event.parsed
    i = int(round(i))
    if (i >= self.parent.NUM_QUEUES):
        i = self.parent.NUM_QUEUES - 1
    if (findLength(self.parent.queues)) < self.parent.MAX_QUEUES_LENGTH:
        self.parent.queues[i].insert(0, event)
    elif i == 0:
        dropOnce(self.parent, event, self.parent.DROP_REASON_LESS_SPACE_IN_QUEUE)
    else:
        x = -1
        for queue in self.parent.queues:
            x = x + 1
            if len(queue) > 0 and x < i:
                e = queue.pop(0)
                dropOnce(self.parent, e, self.parent.DROP_REASON_LESS_SPACE_IN_QUEUE)
                self.parent.queues[i].insert(0, event)
                break


def dropOnce(self, event, reason):
    packet = event.parsed
    drop(self, event)
    self.dropStatistics[reason] = self.dropStatistics[reason] + 1
    if isNormal(packet):
        self.normalRequestsRejected = self.normalRequestsRejected + 1

    if isAttacker(packet):
        self.attackerRequestsRejected = self.attackerRequestsRejected + 1
    None


def process(self, event):
    packet = event.parsed
    key = packet.next.protosrc.__str__() + ":" + event.port.__str__()

    if isNormal(packet):
        self.parent.normalRequestsProcessed = self.parent.normalRequestsProcessed + 1

    if isAttacker(packet):
        self.parent.attackerRequestsProcessed = self.parent.attackerRequestsProcessed + 1

    flowTimeout = calculateFlowTimeOut(self, key)
    addFlow(self.parent, event, key, getCurrentTime() + flowTimeout)
    sleepTime = float(float(self.parent.TIME_SLOT_DURATION) / float(
        self.parent.REQUESTS_PER_TIME_SLOT))
    time.sleep(sleepTime - 0.10)


def calculateFlowTimeOut(self, key):
    trustValue = self.parent.trustValueList[key]
    if trustValue < 0:
        trustValue = trustValue * -1
	flowTimeout = int((trustValue * 1000) * self.parent.TIMEOUT_FACTOR_ATTACKER)
    else:
	flowTimeout = int((trustValue * 1000) * self.parent.TIMEOUT_FACTOR_NORMAL)

    if flowTimeout == 0:
        flowTimeout = self.parent.DEFAULT_TIMEOUT
    return flowTimeout


def load_trust_values_from_file(self, file):
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
    self.trustValueMax = 0
    self.trustValueMin = 10000000
    for key, value in self.trustValueList.items():
        if value > self.trustValueMax:
            self.trustValueMax = value

        if value < self.trustValueMin:
            self.trustValueMin = value


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
    self.blackList[key] = 1


def addFlow(self, event, key, value):
    self.flowList[key] = value


def doesFlowExists(self, event, key):
    if key in self.flowList:
        if self.flowList[key] > getCurrentTime():
            return True
        else:
            self.flowList.pop(key, None)
    return False


def dropFlow(self, event, key, value):
    self.parent.dropList[key] = value
    dropOnce(self.parent, event, self.parent.DROP_REASON_LESS_TRUST_VALUE)


def doesDropFlowExists(self, event, key):
    if key in self.dropList:
        if self.dropList[key] > getCurrentTime():
            return True
        else:
            self.dropList.pop(key, None)
    return False


def flowExist(self, event, key):
    packet = event.parsed
    if doesDropFlowExists(self.parent, event, key):
        if isNormal(packet):
            self.parent.normalRequestsRecieved = self.parent.normalRequestsRecieved + 1
            self.parent.bypassedFlowNormalCount = self.parent.bypassedFlowNormalCount + 1
            # self.parent.normalRequestsProcessed = self.parent.normalRequestsProcessed + 1

        if isAttacker(packet):
            self.parent.attackerRequestsRecieved = self.parent.attackerRequestsRecieved + 1
            self.parent.bypassedFlowAttackerCount = self.parent.bypassedFlowAttackerCount + 1
            # self.parent.attackerRequestsProcessed = self.parent.dropStatistics[
            #                                                      "attackerRequestsProcessed"] + 1
        dropOnce(self.parent, event, self.parent.DROP_REASON_BLACK_LISTED)
        return True
    elif doesFlowExists(self.parent, event, key):
        if isNormal(packet):
            self.parent.normalRequestsRecieved = self.parent.normalRequestsRecieved + 1
            self.parent.bypassedFlowNormalCount = self.parent.bypassedFlowNormalCount + 1
            self.parent.normalRequestsProcessed = self.parent.normalRequestsProcessed + 1

        if isAttacker(packet):
            self.parent.attackerRequestsRecieved = self.parent.attackerRequestsRecieved + 1
            self.parent.attackerRequestsProcessed = self.parent.attackerRequestsProcessed + 1
            self.parent.bypassedFlowAttackerCount = self.parent.bypassedFlowAttackerCount + 1
        # self.parent.dropStatistics["bypassedFlow"] = self.parent.dropStatistics["bypassedFlow"] + 1
        drop(self.parent, event)
        # self.parent.moreRequestsToProcess = self.parent.moreRequestsToProcess - 1
        return True

    return False


def getCurrentTime():
    return int(round(time.time() * 1000))


def controlerUnderAttack(self):
    if (findLength(self.queues)) > int(self.MAX_QUEUES_LENGTH * self.ATTACK_THRESHOLD):
        return True
    else:
        return False


def isNormal(packet):
    if packet.next.protosrc.__str__()[:4] == ("10.0"):
        return True
    else:
        return False


def isAttacker(packet):
    if packet.next.protosrc.__str__()[:4] == ("10.1"):
        return True
    else:
        return False


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
        self.connection = connection
        self.transparent = transparent
        self.hold_down_expired = _flood_delay == 0
        # Our table
        self.event_list = list()
        self.trustValueList = {}
        self.abnormalThresholdList = {}
        self.blackList = {}
        self.flowList = {}
        self.dropList = {}

        self.NUM_QUEUES = 5
        self.queues = list()
        for i in range(self.NUM_QUEUES):
            self.queues.append(list())

        self.thisTimeSlot = {}

        self.dropStatistics = {}
        self.REQUESTS_PER_TIME_SLOT = 100
        self.EXPECTED_REQUESTS_THIS_TIME_SLOT = 150
        self.moreRequestsToProcess = 100
        self.MAX_QUEUES_LENGTH = 100
        self.TIMEOUT_FACTOR_NORMAL = 0.1
        self.TIMEOUT_FACTOR_ATTACKER = 10
        self.DEFAULT_TIMEOUT = 5000
        self.DEFAULT_ABNORMAL_THRESHOLD = 2
        self.ATTACK_THRESHOLD = 0.7
        self.trustValueMininum = 1
        self.DROP_REASON_ABNORMAL_THRESHOLD = "dropAbnormalThreshold";
        self.DROP_REASON_LESS_TRUST_VALUE = "dropLessTrustValue";
        self.DROP_REASON_BLACK_LISTED = "dropBlackListed";
        self.DROP_REASON_LESS_SPACE_IN_QUEUE = "dropLessSpaceInQueue";
        self.dropStatistics[self.DROP_REASON_ABNORMAL_THRESHOLD] = 0
        self.dropStatistics[self.DROP_REASON_LESS_TRUST_VALUE] = 0
        self.dropStatistics[self.DROP_REASON_BLACK_LISTED] = 0
        self.dropStatistics[self.DROP_REASON_LESS_SPACE_IN_QUEUE] = 0
        self.bypassedFlowNormalCount = 0
        self.bypassedFlowAttackerCount = 0
        self.currentTimeSlot = 1
        self.TIME_SLOT_DURATION = 12
        self.trustValueMax = 2
        self.trustValueMin = 1
        self.totalRequestsProcessed = 0
        self.processedFromQueue = list()
        for i in range(self.NUM_QUEUES):
            self.processedFromQueue.append(0)

        self.normalRequestsRecieved = 0
        self.normalRequestsRejected = 0
        self.attackerRequestsRecieved = 0
        self.attackerRequestsRejected = 0
        self.normalRequestsProcessed = 0
        self.attackerRequestsProcessed = 0

        load_abnormal_threshold_values_from_file(self, "file2.txt")

        self.thread_queuing = TrustAndQueuingManagment(self)
        self.thread_queuing.start()
        self.thread_scheduaing = Scheduling(self)
        self.thread_scheduaing.start()

        self.thread_timeslottrigger = TimeSlotTrigger(self)
        self.thread_timeslottrigger.start()

        self.thread_display = DisplayManager(self)
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
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.name = "DisplayManager"
        load_trust_values_from_file(parent, "after50Me.txt")
        self.parent = parent
        log.debug("DisplayManager thread launched")

    def run(self):
        print("Starting " + self.name)
        while (1):
            os.system('clear')
            print("Current Time Slot : %d" % (self.parent.currentTimeSlot))
            print("Requests processed in this time slot : %d" % (self.parent.REQUESTS_PER_TIME_SLOT-self.parent.moreRequestsToProcess))

            for i in range(self.parent.NUM_QUEUES):
                print("Requests processed from Queue %d : %d" % (i + 1, self.parent.processedFromQueue[i]))

            print("Normal requests recieved : %d" % (self.parent.normalRequestsRecieved))
            print("Attacker requests recieved : %d" % (self.parent.attackerRequestsRecieved))
            print("Total requests recieved : %d" % (
                    self.parent.attackerRequestsRecieved + self.parent.normalRequestsRecieved))

            print("Normal requests Processed : %d" % (self.parent.normalRequestsProcessed))
            print("Attacker requests Processed : %d" % (self.parent.attackerRequestsProcessed))
            print("Total Requests processed : %d" % (self.parent.totalRequestsProcessed))

            print("Normal requests rejected : %d" % (self.parent.normalRequestsRejected))
            print("Attackers requests rejected : %d" % (self.parent.attackerRequestsRejected))
            print("Bypassed Normal : %d" % (self.parent.bypassedFlowNormalCount))
            print("Bypassed Attacker : %d" % (self.parent.bypassedFlowAttackerCount))
            print("Bypassed total : %d" % (
                    self.parent.bypassedFlowNormalCount + self.parent.bypassedFlowAttackerCount))

            print("dropped due to abnormal threshold  : %d" % (
                self.parent.dropStatistics[self.parent.DROP_REASON_ABNORMAL_THRESHOLD]))
            print("dropped due to less trust value : %d" % (
                self.parent.dropStatistics[self.parent.DROP_REASON_LESS_TRUST_VALUE]))
            print(
                "dropped because blacklisted : %d" % (self.parent.dropStatistics[self.parent.DROP_REASON_BLACK_LISTED]))
            print("dropped due to no space in queue : %d" % (
                self.parent.dropStatistics[self.parent.DROP_REASON_LESS_SPACE_IN_QUEUE]))
            print("total dropped : %d" % (
                    self.parent.dropStatistics[self.parent.DROP_REASON_LESS_SPACE_IN_QUEUE] +
                    self.parent.dropStatistics[
                        self.parent.DROP_REASON_LESS_TRUST_VALUE] +
                    self.parent.dropStatistics[self.parent.DROP_REASON_ABNORMAL_THRESHOLD] + self.parent.dropStatistics[
                        self.parent.DROP_REASON_BLACK_LISTED]))

            print("Unprocessed Events: %d" % (len(self.parent.event_list)))
            print("Requests in queue 1 : %d" % (len(self.parent.queues[0])))
            print("Requests in queue 2 : %d" % (len(self.parent.queues[1])))
            print("Requests in queue 3 : %d" % (len(self.parent.queues[2])))
            print("Requests in queue 4 : %d" % (len(self.parent.queues[3])))
            print("Requests in queue 5 : %d" % (len(self.parent.queues[4])))
            print("Length of trust value list : %d" % (len(self.parent.trustValueList)))
            print("Maximum trust value : %d" % (self.parent.trustValueMax))
            print("Mininum trust value : %d" % (self.parent.trustValueMin))

            print("thisTimeSlot list : %d" % (len(self.parent.thisTimeSlot)))

            time.sleep(0.5)


class TimeSlotTrigger(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.name = "TimeSlotTrigger"
        load_trust_values_from_file(parent, "after50Me.txt")
        self.parent = parent
        log.debug("TimeSlotTrigger thread launched")

    def run(self):
        print("Starting " + self.name)
        while (1):
            time.sleep(self.parent.TIME_SLOT_DURATION)
            self.parent.thisTimeSlot.clear()
            self.parent.currentTimeSlot = self.parent.currentTimeSlot + 1
            self.parent.moreRequestsToProcess =  self.parent.REQUESTS_PER_TIME_SLOT
            self.parent.EXPECTED_REQUESTS_THIS_TIME_SLOT = self.parent.EXPECTED_REQUESTS_THIS_TIME_SLOT + 2
            save_trust_values_in_file(self.parent, "file1.txt", self.parent.trustValueList)
            save_abnormal_threshold_values_in_file(self.parent, "file2.txt", self.parent.abnormalThresholdList)


def anotherRequestRecieved(self, packet, key):
    if isNormal(packet):
        self.parent.normalRequestsRecieved = self.parent.normalRequestsRecieved + 1

    if isAttacker(packet):
        self.parent.attackerRequestsRecieved = self.parent.attackerRequestsRecieved + 1

    if key in self.parent.thisTimeSlot:
        self.parent.thisTimeSlot[key] = self.parent.thisTimeSlot[key] + 1
    else:
        self.parent.thisTimeSlot[key] = 1
    None


def shouldProcess(self, event):
    packet = event.parsed
    timeslotKey = packet.next.protosrc.__str__() + ":" + event.port.__str__() + "->" + packet.dst.__str__()
    if timeslotKey in self.parent.thisTimeSlot:
        self.parent.thisTimeSlot[timeslotKey] = self.parent.thisTimeSlot[timeslotKey] + 1
    else:
        self.parent.thisTimeSlot[timeslotKey] = 1

    if self.parent.thisTimeSlot[timeslotKey] % 3 != 1:
        drop(self.parent, event)
        return False
    else:
        return True


class TrustAndQueuingManagment(threading.Thread):
    def __init__(self, parent):
        threading.Thread.__init__(self)
        self.name = "queueing managment"
        load_trust_values_from_file(parent, "after50Me.txt")
        self.parent = parent
        log.debug("TrustAndQueuingManagment thread launched")

    def run(self):
        print("Starting " + self.name)
        while 1:
            if len(self.parent.event_list) > 0:
                event = self.parent.event_list.pop()
                droped = False
                packet = event.parsed
                # print("new event found %d" % (len(self.parent.event_list)))
                key = packet.next.protosrc.__str__() + ":" + event.port.__str__()

                if shouldProcess(self, event):
                    if flowExist(self, event, key):
                        None
                    else:
                        anotherRequestRecieved(self, packet, key)

                        if key not in self.parent.trustValueList:
                            self.parent.trustValueList[key] = 1
			    calculateMaxMinTrustValue(self.parent)
                            self.parent.abnormalThresholdList[key] = self.parent.DEFAULT_ABNORMAL_THRESHOLD
                        else:
                            if self.parent.thisTimeSlot[key] > self.parent.abnormalThresholdList[key]:
                                dropOnce(self.parent, event, self.parent.DROP_REASON_ABNORMAL_THRESHOLD)
                                droped = True
                                self.parent.abnormalThresholdList[key] = self.parent.abnormalThresholdList[key] + 1
                            else:
                                if controlerUnderAttack(self.parent):
                                    self.parent.trustValueList[key] = self.parent.trustValueList[key] - 1
                                else:
                                    self.parent.trustValueList[key] = self.parent.trustValueList[key] + 1

                                calculateMaxMinTrustValue(self.parent)

                            if (self.parent.trustValueList[key] < self.parent.trustValueMininum):
                                flowTimeout = calculateFlowTimeOut(self, key)
                                dropFlow(self, event, key, getCurrentTime() + flowTimeout)
                                droped = True
                        if droped == False:
                            addInQueue(self, event, self.parent.trustValueList[key])

            else:
                time.sleep(0.3)
                continue;

        print("Exiting " + self.name)


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
