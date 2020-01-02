// vscptcpip.cpp: implementation of the CTcpipLink class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP Project (http://www.vscp.org)
//
// Copyright (C) 2000-2020 Ake Hedman,
// Grodans Paradis AB, <akhe@grodansparadis.com>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#include <list>
#include <map>
#include <string>

#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include <expat.h>

#include <hlo.h>
#include <remotevariablecodes.h>
#include <vscp.h>
#include <vscp_class.h>
#include <vscp_type.h>
#include <vscpdatetime.h>
#include <vscphelper.h>
#include <vscpremotetcpif.h>

#include "tcpiplink.h"

// Buffer for XML parser
#define XML_BUFF_SIZE 50000

// Forward declaration
void*
workerThreadReceive(void* pData);
void*
workerThreadSend(void* pData);

//////////////////////////////////////////////////////////////////////
// CTcpipLink
//

CTcpipLink::CTcpipLink()
{
    m_bQuit = false;
    m_pthreadSend = NULL;
    m_pthreadReceive = NULL;
    vscp_clearVSCPFilter(&m_rxfilter); // Accept all events
    vscp_clearVSCPFilter(&m_txfilter); // Send all events
    m_responseTimeout = TCPIP_DEFAULT_INNER_RESPONSE_TIMEOUT;

    sem_init(&m_semSendQueue, 0, 0);
    sem_init(&m_semReceiveQueue, 0, 0);

    pthread_mutex_init(&m_mutexSendQueue, NULL);
    pthread_mutex_init(&m_mutexReceiveQueue, NULL);
}

//////////////////////////////////////////////////////////////////////
// ~CTcpipLink
//

CTcpipLink::~CTcpipLink()
{
    close();

    sem_destroy(&m_semSendQueue);
    sem_destroy(&m_semReceiveQueue);

    pthread_mutex_destroy(&m_mutexSendQueue);
    pthread_mutex_destroy(&m_mutexReceiveQueue);

    // Close syslog channel
    closelog();
}

// ----------------------------------------------------------------------------

/*
    XML configuration
    -----------------

    <setup host="localhost"
              port="9598"
              user="admin"
              password="secret"
              rxfilter=""
              rxmask=""
              txfilter=""
              txmask=""
              responsetimeout="2000" />
*/

// ----------------------------------------------------------------------------

int depth_setup_parser = 0;

void
startSetupParser(void* data, const char* name, const char** attr)
{
    CTcpipLink* pObj = (CTcpipLink*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "setup")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "host")) {
                if (!attribute.empty()) {
                    pObj->m_hostRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "port")) {
                if (!attribute.empty()) {
                    pObj->m_portRemote = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "user")) {
                if (!attribute.empty()) {
                    pObj->m_usernameRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "password")) {
                if (!attribute.empty()) {
                    pObj->m_passwordRemote = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "rxfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_rxfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpiplink] Unable to read "
                               "event receive filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "rxmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_rxfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpiplink] Unable to read "
                               "event receive mask.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txfilter")) {
                if (!attribute.empty()) {
                    if (!vscp_readFilterFromString(&pObj->m_txfilter,
                                                   attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpiplink] Unable to read "
                               "event transmit filter.");
                    }
                }
            } else if (0 == strcasecmp(attr[i], "txmask")) {
                if (!attribute.empty()) {
                    if (!vscp_readMaskFromString(&pObj->m_txfilter,
                                                 attribute)) {
                        syslog(LOG_ERR,
                               "[vscpl2drv-tcpiplink] Unable to read "
                               "event transmit mask.");
                    }
                }
            } else if (0 == strcmp(attr[i], "responsetimeout")) {
                if (!attribute.empty()) {
                    pObj->m_responseTimeout = vscp_readStringValue(attribute);
                }
            }
        }
    }

    depth_setup_parser++;
}

void
endSetupParser(void* data, const char* name)
{
    depth_setup_parser--;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CTcpipLink::open(std::string& path, const cguid& guid)
{
    // Set GUID
    m_guid = guid;

    // Save path to config file
    m_path = path;

    // Read configuration file
    if (!doLoadConfig()) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Failed to load configuration file [%s]",
               path.c_str());
    }

    // // Parse the configuration string.
    // std::deque<std::string> tokens;
    // vscp_split(tokens, std::string(pConfig), ";");

    // // Check for remote host in configuration string
    // if (!tokens.empty()) {
    //     // Get remote interface
    //     m_hostRemote = tokens.front();
    //     tokens.pop_front();
    // }

    // // Check for remote port in configuration string
    // if (!tokens.empty()) {
    //     // Get remote port
    //     m_portRemote = vscp_readStringValue(tokens.front());
    //     tokens.pop_front();
    // }

    // // Check for remote user in configuration string
    // if (!tokens.empty()) {
    //     // Get remote username
    //     m_usernameRemote = tokens.front();
    //     tokens.pop_front();
    // }

    // // Check for remote password in configuration string
    // if (!tokens.empty()) {
    //     // Get remote password
    //     m_passwordRemote = tokens.front();
    //     tokens.pop_front();
    // }

    // std::string strRxFilter;
    // // Check for filter in configuration string
    // if (!tokens.empty()) {
    //     // Get filter
    //     strRxFilter = tokens.front();
    //     tokens.pop_front();
    //     vscp_readFilterFromString(&m_rxfilter, strRxFilter);
    // }

    // // Check for mask in configuration string
    // std::string strRxMask;
    // if (!tokens.empty()) {
    //     // Get mask
    //     strRxMask = tokens.front();
    //     tokens.pop_front();
    //     vscp_readMaskFromString(&m_rxfilter, strRxMask);
    // }

    // std::string strTxFilter;
    // // Check for filter in configuration string
    // if (!tokens.empty()) {
    //     // Get filter
    //     strTxFilter = tokens.front();
    //     tokens.pop_front();
    //     vscp_readFilterFromString(&m_txfilter, strTxFilter);
    // }

    // // Check for mask in configuration string
    // std::string strTxMask;
    // if (!tokens.empty()) {
    //     // Get mask
    //     strTxMask = tokens.front();
    //     tokens.pop_front();
    //     vscp_readMaskFromString(&m_txfilter, strTxMask);
    // }

    // // Check for response timout in configuration string
    // std::string strResponseTimout;
    // if (!tokens.empty()) {
    //     // Get response timout
    //     strResponseTimout = tokens.front();
    //     tokens.pop_front();
    //     m_responseTimeout = vscp_readStringValue(strResponseTimout);
    // }

    // start the workerthread
    if (pthread_create(m_pthreadSend, NULL, workerThreadSend, this)) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Unable to start send worker thread.");
        return false;
    }

    if (pthread_create(m_pthreadReceive, NULL, workerThreadReceive, this)) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Unable to start receive worker thread.");
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipLink::close(void)
{
    // Do nothing if already terminated
    if (m_bQuit)
        return;

    m_bQuit = true; // terminate the thread
    sleep(1);       // Give the thread some time to terminate
}

// ----------------------------------------------------------------------------

int depth_hlo_parser = 0;

void
startHLOParser(void* data, const char* name, const char** attr)
{
    CHLO* pObj = (CHLO*)data;
    if (NULL == pObj)
        return;

    if ((0 == strcmp(name, "vscp-cmd")) && (0 == depth_setup_parser)) {

        for (int i = 0; attr[i]; i += 2) {

            std::string attribute = attr[i + 1];
            vscp_trim(attribute);

            if (0 == strcasecmp(attr[i], "op")) {
                if (!attribute.empty()) {
                    pObj->m_op = vscp_readStringValue(attribute);
                    vscp_makeUpper(attribute);
                    if (attribute == "VSCP-NOOP") {
                        pObj->m_op = HLO_OP_NOOP;
                    } else if (attribute == "VSCP-READVAR") {
                        pObj->m_op = HLO_OP_READ_VAR;
                    } else if (attribute == "VSCP-WRITEVAR") {
                        pObj->m_op = HLO_OP_WRITE_VAR;
                    } else if (attribute == "VSCP-LOAD") {
                        pObj->m_op = HLO_OP_LOAD;
                    } else if (attribute == "VSCP-SAVE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else if (attribute == "CALCULATE") {
                        pObj->m_op = HLO_OP_SAVE;
                    } else {
                        pObj->m_op = HLO_OP_UNKNOWN;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "name")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    pObj->m_name = attribute;
                }
            } else if (0 == strcasecmp(attr[i], "type")) {
                if (!attribute.empty()) {
                    pObj->m_varType = vscp_readStringValue(attribute);
                }
            } else if (0 == strcasecmp(attr[i], "value")) {
                if (!attribute.empty()) {
                    if (vscp_base64_std_decode(attribute)) {
                        pObj->m_value = attribute;
                    }
                }
            } else if (0 == strcasecmp(attr[i], "full")) {
                if (!attribute.empty()) {
                    vscp_makeUpper(attribute);
                    if ("TRUE" == attribute) {
                        pObj->m_bFull = true;
                    } else {
                        pObj->m_bFull = false;
                    }
                }
            }
        }
    }

    depth_hlo_parser++;
}

void
endHLOParser(void* data, const char* name)
{
    depth_hlo_parser--;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// parseHLO
//

bool
CTcpipLink::parseHLO(uint16_t size, uint8_t* inbuf, CHLO* phlo)
{
    // Check pointers
    if (NULL == inbuf) {
        syslog(
          LOG_ERR,
          "[vscpl2drv-tcpiplink] HLO parser: HLO in-buffer pointer is NULL.");
        return false;
    }

    if (NULL == phlo) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] HLO parser: HLO obj pointer is NULL.");
        return false;
    }

    if (!size) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] HLO parser: HLO buffer size is zero.");
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startHLOParser, endHLOParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    // Copy in the HLO object
    memcpy(buf, inbuf, size);

    if (!XML_ParseBuffer(xmlParser, size, size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpiplink] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

// ----------------------------------------------------------------------------

///////////////////////////////////////////////////////////////////////////////
// loadConfiguration
//

bool
CTcpipLink::doLoadConfig(void)
{
    FILE* fp;
    
    fp = fopen(m_path.c_str(), "r");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Failed to open configuration file [%s]",
               m_path.c_str());
        return false;
    }

    XML_Parser xmlParser = XML_ParserCreate("UTF-8");
    XML_SetUserData(xmlParser, this);
    XML_SetElementHandler(xmlParser, startSetupParser, endSetupParser);

    void* buf = XML_GetBuffer(xmlParser, XML_BUFF_SIZE);

    size_t file_size = 0;
    file_size = fread(buf, sizeof(char), XML_BUFF_SIZE, fp);

    if (!XML_ParseBuffer(xmlParser, file_size, file_size == 0)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpiplink] Failed parse XML setup.");
        XML_ParserFree(xmlParser);
        return false;
    }

    XML_ParserFree(xmlParser);

    return true;
}

#define TEMPLATE_SAVE_CONFIG                                                   \
    "<setup "                                                                  \
    " host=\"%s\" "                                                            \
    " port=\"%d\" "                                                            \
    " user=\"%s\" "                                                            \
    " password=\"%s\" "                                                        \
    " rxfilter=\"%s\" "                                                        \
    " rxmask=\"%s\" "                                                          \
    " txfilter=\"%s\" "                                                        \
    " txmask=\"%s\" "                                                          \
    " responsetimeout=\"%lu\" "                                                \
    "/>"

///////////////////////////////////////////////////////////////////////////////
// saveConfiguration
//

bool
CTcpipLink::doSaveConfig(void)
{
    char buf[2048]; // Working buffer

    std::string strRxFilter, strRxMask;
    std::string strTxFilter, strTxMask;
    vscp_writeFilterToString( strRxFilter, &m_rxfilter );
    vscp_writeFilterToString( strRxMask, &m_rxfilter );
    vscp_writeFilterToString( strTxFilter, &m_txfilter );
    vscp_writeFilterToString( strTxMask, &m_txfilter );

    sprintf( buf, 
        TEMPLATE_SAVE_CONFIG,
        m_hostRemote.c_str(),
        m_portRemote,
        m_usernameRemote.c_str(),
        m_passwordRemote.c_str(),
        strRxFilter.c_str(),
        strRxMask.c_str(),
        strTxFilter.c_str(),
        strTxMask.c_str(),
        (long unsigned int)m_responseTimeout );

    FILE* fp;
    
    fp = fopen(m_path.c_str(), "w");
    if (NULL == fp) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Failed to open configuration file [%s] for write",
               m_path.c_str());
        return false;
    }

    if ( strlen(buf) != fwrite( buf, sizeof(char), strlen(buf), fp ) ) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Failed to write configuration file [%s] ",
               m_path.c_str());
        fclose (fp);       
        return false;
    }

    fclose(fp);
    return true;
}

///////////////////////////////////////////////////////////////////////////////
// handleHLO
//

bool
CTcpipLink::handleHLO(vscpEvent* pEvent)
{
    char buf[512]; // Working buffer
    vscpEventEx ex;

    // Check pointers
    if (NULL == pEvent) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] HLO handler: NULL event pointer.");
        return false;
    }

    CHLO hlo;
    if (!parseHLO(pEvent->sizeData, pEvent->pdata, &hlo)) {
        syslog(LOG_ERR, "[vscpl2drv-tcpiplink] Failed to parse HLO.");
        return false;
    }

    ex.obid = 0;
    ex.head = 0;
    ex.timestamp = vscp_makeTimeStamp();
    vscp_setEventExToNow(&ex); // Set time to current time
    ex.vscp_class = VSCP_CLASS2_PROTOCOL;
    ex.vscp_type = VSCP2_TYPE_PROTOCOL_HIGH_LEVEL_OBJECT;
    m_guid.writeGUID(ex.GUID);

    switch (hlo.m_op) {

        case HLO_OP_NOOP:
            // Send positive response
            sprintf(buf,
                    HLO_CMD_REPLY_TEMPLATE,
                    "noop",
                    "OK",
                    "NOOP commaned executed correctly.");

            memset(ex.data, 0, sizeof(ex.data));
            ex.sizeData = strlen(buf);
            memcpy(ex.data, buf, ex.sizeData);

            // Put event in receive queue
            return eventExToReceiveQueue(ex);

        case HLO_OP_READ_VAR:
            if ("REMOTE-HOST" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-host",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_STRING,
                        vscp_convertToBase64(m_hostRemote).c_str());
            } else if ("REMOTE-PORT" == hlo.m_name) {
                char ibuf[80];
                sprintf(ibuf, "%d", m_portRemote);
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-port",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(ibuf).c_str());
            } else if ("REMOTE-USER" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-user",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(m_usernameRemote).c_str());
            } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "remote-password",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                        vscp_convertToBase64(m_passwordRemote).c_str());
            } else if ("TIMEOUT-RESPONSE" == hlo.m_name) {
                char ibuf[80];
                sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                sprintf(buf,
                        HLO_READ_VAR_REPLY_TEMPLATE,
                        "timeout-response",
                        "OK",
                        VSCP_REMOTE_VARIABLE_CODE_LONG,
                        vscp_convertToBase64(ibuf).c_str());
            }
            break;

        case HLO_OP_WRITE_VAR:
            if ("REMOTE-HOST" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-host",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_hostRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "enable-sunrise",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_hostRemote).c_str());
                }
            } else if ("REMOTE-PORT" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-port",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be integer.");
                } else {                    
                    m_portRemote = vscp_readStringValue(hlo.m_value);
                    char ibuf[80];
                    sprintf(ibuf, "%d", m_portRemote);
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-port",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_INTEGER,
                            vscp_convertToBase64(ibuf).c_str());
                }
            } else if ("REMOTE-USER" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-port",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_usernameRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-user",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_usernameRemote).c_str());
                }
            } else if ("REMOTE-PASSWORD" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_STRING != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "remote-password",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be string.");
                } else {
                    m_passwordRemote = hlo.m_value;
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "remote-password!",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_STRING,
                            vscp_convertToBase64(m_passwordRemote).c_str());
                }
            } else if ("TIMEOUT-RESPONSE¤" == hlo.m_name) {
                if (VSCP_REMOTE_VARIABLE_CODE_INTEGER != hlo.m_varType) {
                    // Wrong variable type
                    sprintf(buf,
                            HLO_READ_VAR_ERR_REPLY_TEMPLATE,
                            "timeout-response",
                            ERR_VARIABLE_WRONG_TYPE,
                            "Variable type should be uint32.");
                } else {                    
                    m_responseTimeout = vscp_readStringValue(hlo.m_value);
                    char ibuf[80];
                    sprintf(ibuf, "%lu", (long unsigned int)m_responseTimeout);
                    sprintf(buf,
                            HLO_READ_VAR_REPLY_TEMPLATE,
                            "timeout-response",
                            "OK",
                            VSCP_REMOTE_VARIABLE_CODE_UINT32,
                            vscp_convertToBase64(ibuf).c_str());
                }
            }
            break;

        // Save configuration
        case HLO_OP_SAVE:
            doSaveConfig();
            break;

        // Load configuration
        case HLO_OP_LOAD:
            doLoadConfig();
            break;

        // Connect tyo remote host
        case HLO_OP_LOCAL_CONNECT:
            break;    

        // Disconnect from remote host
        case HLO_OP_LOCAL_DISCONNECT:
            break;
  
        default:
            break;
    };

    return true;
}

///////////////////////////////////////////////////////////////////////////////
// eventExToReceiveQueue
//

bool
CTcpipLink::eventExToReceiveQueue(vscpEventEx& ex)
{
    vscpEvent* pev = new vscpEvent();
    if (!vscp_convertEventExToEvent(pev, &ex)) {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Failed to convert event from ex to ev.");
        vscp_deleteEvent(pev);
        return false;
    }
    if (NULL != pev) {
        if (vscp_doLevel2Filter(pev, &m_rxfilter)) {
            pthread_mutex_lock(&m_mutexReceiveQueue);
            m_receiveList.push_back(pev);
            sem_post(&m_semReceiveQueue);
            pthread_mutex_unlock(&m_mutexReceiveQueue);
        } else {
            vscp_deleteEvent(pev);
        }
    } else {
        syslog(LOG_ERR,
               "[vscpl2drv-tcpiplink] Unable to allocate event storage.");
    }
    return true;
}

//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool
CTcpipLink::addEvent2SendQueue(const vscpEvent* pEvent)
{
    pthread_mutex_lock(&m_mutexSendQueue);
    m_sendList.push_back((vscpEvent*)pEvent);
    sem_post(&m_semSendQueue);
    pthread_mutex_lock(&m_mutexSendQueue);
    return true;
}

//////////////////////////////////////////////////////////////////////
// Send worker thread
//

void*
workerThreadSend(void* pData)
{
    bool bRemoteConnectionLost = false;

    CTcpipLink* pObj = (CTcpipLink*)pData;
    if (NULL == pObj)
        return NULL;

retry_send_connect:

    // Open remote interface
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemote.doCmdOpen(pObj->m_hostRemote,
                                    pObj->m_portRemote,
                                    pObj->m_usernameRemote,
                                    pObj->m_passwordRemote)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Error while opening remote VSCP TCP/IP "
                            "interface. Terminating!");

        // Give the server some time to become active
        for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
             loopcnt++) {
            sleep(1);
            if (pObj->m_bQuit)
                return NULL;
        }

        goto retry_send_connect;
    }

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Connect to remote VSCP TCP/IP interface [SEND].");

    // Find the channel id
    pObj->m_srvRemote.doCmdGetChannelID(&pObj->txChannelID);

    while (!pObj->m_bQuit) {

        // Make sure the remote connection is up
        if (!pObj->m_srvRemote.isConnected()) {

            if (!bRemoteConnectionLost) {
                bRemoteConnectionLost = true;
                pObj->m_srvRemote.doCmdClose();
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Lost connection to remote host [SEND].");
            }

            // Wait before we try to connect again
            sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

            if (VSCP_ERROR_SUCCESS !=
                pObj->m_srvRemote.doCmdOpen(pObj->m_hostRemote,
                                            pObj->m_portRemote,
                                            pObj->m_usernameRemote,
                                            pObj->m_passwordRemote)) {
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Reconnected to remote host [SEND].");

                // Find the channel id
                pObj->m_srvRemote.doCmdGetChannelID(&pObj->txChannelID);

                bRemoteConnectionLost = false;
            }

            continue;
        }

        if ((-1 == vscp_sem_wait(&pObj->m_semSendQueue, 500)) &&
            errno == ETIMEDOUT) {
            continue;
        }

        // Check if there is event(s) to send
        if (pObj->m_sendList.size()) {

            // Yes there are data to send
            pthread_mutex_lock(&pObj->m_mutexSendQueue);
            vscpEvent* pEvent = pObj->m_sendList.front();
            // Check if event should be filtered away
            if (!vscp_doLevel2Filter(pEvent, &pObj->m_txfilter)) {
                pthread_mutex_unlock(&pObj->m_mutexSendQueue);
                continue;
            }
            pObj->m_sendList.pop_front();
            pthread_mutex_unlock(&pObj->m_mutexSendQueue);

            // Only HLO object event is of interst to us
            if ((VSCP_CLASS2_PROTOCOL == pEvent->vscp_class) &&
                (VSCP2_TYPE_PROTOCOL_HIGH_LEVEL_OBJECT == pEvent->vscp_type)) {
                pObj->handleHLO(pEvent);
            }

            if (NULL == pEvent)
                continue;

            // Yes there are data to send
            // Send it out to the remote server

            pObj->m_srvRemote.doCmdSend(pEvent);
            vscp_deleteEvent_v2(&pEvent);
        }
    }

    // Close the channel
    pObj->m_srvRemote.doCmdClose();

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Disconnect from remote VSCP TCP/IP interface [SEND].");

    return NULL;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

void*
workerThreadReceive(void* pData)
{
    bool bRemoteConnectionLost = false;
    __attribute__((unused)) bool bActivity = false;

    CTcpipLink* pObj = (CTcpipLink*)pData;
    if (NULL == pObj)
        return NULL;

retry_receive_connect:

    // Open remote interface
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemote.doCmdOpen(pObj->m_hostRemote,
                                    pObj->m_portRemote,
                                    pObj->m_usernameRemote,
                                    pObj->m_passwordRemote)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Error while opening remote VSCP TCP/IP "
                            "interface. Terminating!");

        // Give the server some time to become active
        for (int loopcnt = 0; loopcnt < VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME;
             loopcnt++) {
            sleep(1);
            if (pObj->m_bQuit)
                return NULL;
        }

        goto retry_receive_connect;
    }

    syslog(LOG_ERR,
           "%s %s ",
           VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
           (const char*)"Connect to remote VSCP TCP/IP interface [RECEIVE].");

    // Set receive filter
    if (VSCP_ERROR_SUCCESS !=
        pObj->m_srvRemote.doCmdFilter(&pObj->m_rxfilter)) {
        syslog(LOG_ERR,
               "%s %s ",
               VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
               (const char*)"Failed to set receiving filter.");
    }

    // Enter the receive loop
    pObj->m_srvRemote.doCmdEnterReceiveLoop();

    __attribute__((unused)) vscpEventEx eventEx;
    while (!pObj->m_bQuit) {

        // Make sure the remote connection is up
        if (!pObj->m_srvRemote.isConnected() ||
            ((vscp_getMsTimeStamp() - pObj->m_srvRemote.getlastResponseTime()) >
             (VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME * 1000))) {

            if (!bRemoteConnectionLost) {

                bRemoteConnectionLost = true;
                pObj->m_srvRemote.doCmdClose();
                syslog(
                  LOG_ERR,
                  "%s %s ",
                  VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                  (const char*)"Lost connection to remote host [Receive].");
            }

            // Wait before we try to connect again
            sleep(VSCP_TCPIPLINK_DEFAULT_RECONNECT_TIME);

            if (VSCP_ERROR_SUCCESS !=
                pObj->m_srvRemote.doCmdOpen(pObj->m_hostRemote,
                                            pObj->m_portRemote,
                                            pObj->m_usernameRemote,
                                            pObj->m_passwordRemote)) {
                syslog(LOG_ERR,
                       "%s %s ",
                       VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
                       (const char*)"Reconnected to remote host [Receive].");
                bRemoteConnectionLost = false;
            }

            // Enter the receive loop
            pObj->m_srvRemote.doCmdEnterReceiveLoop();

            continue;
        }

        // Check if remote server has something to send to us
        vscpEvent* pEvent = new vscpEvent;
        if (NULL != pEvent) {

            pEvent->sizeData = 0;
            pEvent->pdata = NULL;

            if (CANAL_ERROR_SUCCESS ==
                pObj->m_srvRemote.doCmdBlockingReceive(pEvent)) {

                // Filter is handled at server side. We check so we don't
                // receive things we send ourself.
                if (pObj->txChannelID != pEvent->obid) {
                    pthread_mutex_lock(&pObj->m_mutexReceiveQueue);
                    pObj->m_receiveList.push_back(pEvent);
                    sem_post(&pObj->m_semReceiveQueue);
                    pthread_mutex_unlock(&pObj->m_mutexReceiveQueue);
                } else {
                    vscp_deleteEvent(pEvent);
                }

            } else {
                vscp_deleteEvent(pEvent);
            }
        }
    }

    // Close the channel
    pObj->m_srvRemote.doCmdClose();

    syslog(
      LOG_ERR,
      "%s %s ",
      VSCP_TCPIPLINK_SYSLOG_DRIVER_ID,
      (const char*)"Disconnect from remote VSCP TCP/IP interface [RECEIVE].");

    return NULL;
}
