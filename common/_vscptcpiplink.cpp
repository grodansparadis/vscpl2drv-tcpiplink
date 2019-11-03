// vscptcpip.cpp: implementation of the CTcpipLink class.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
// 
// This file is part of the VSCP Project (http://www.vscp.org) 
//
// Copyright (C) 2000-2019 Ake Hedman, 
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

#ifdef WIN32
#include <winsock2.h>
#endif

#include <stdio.h>

#ifndef WIN32
#include "unistd.h"
#include "syslog.h"
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>
#include <sys/time.h>
#endif

#include "stdlib.h"
#include <string.h>
#include "limits.h"
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>


#include "wx/wxprec.h"
#include "wx/wx.h"
#include "wx/defs.h"
#include "wx/app.h"
#include <wx/xml/xml.h>
#include <wx/listimpl.cpp>
#include <wx/thread.h>
#include <wx/tokenzr.h>
#include <wx/datetime.h>

#include <vscphelper.h>
#include <vscpremotetcpif.h>
#include <vscp_type.h>
#include <vscp_class.h>
#include "vscptcpiplink.h"


//////////////////////////////////////////////////////////////////////
// CTcpipLink
//

CTcpipLink::CTcpipLink()
{
	m_bQuit = false;
	m_pthreadSend = NULL;
    m_pthreadReceive = NULL;
	vscp_clearVSCPFilter(&m_vscpfilter); // Accept all events
	::wxInitialize();
}

//////////////////////////////////////////////////////////////////////
// ~CTcpipLink
//

CTcpipLink::~CTcpipLink()
{
	close();
	::wxUninitialize();
}


//////////////////////////////////////////////////////////////////////
// open
//
//

bool
CTcpipLink::open(const char *pUsername,
                    const char *pPassword,
                    const char *pHost,
                    short port,
                    const char *pPrefix,
                    const char *pConfig)
{
	bool rv = true;
	wxString wxstr = wxString::FromAscii(pConfig);

	m_usernameLocal = wxString::FromAscii(pUsername);
	m_passwordLocal = wxString::FromAscii(pPassword);
	m_hostLocal = wxString::FromAscii(pHost);
	m_portLocal = port;
	m_prefix = wxString::FromAscii(pPrefix);

	// Parse the configuration string. It should
	// have the following form
	// interface  host;port;use;password
	wxStringTokenizer tkz(wxString::FromAscii(pConfig), _(";"));

	// Check for remote host in configuration string
	if (tkz.HasMoreTokens()) {
		// Interface
		m_hostRemote = tkz.GetNextToken();
	}
	
	// Check for remote port in configuration string
	if (tkz.HasMoreTokens()) {
		// Interface
		m_portRemote = vscp_readStringValue(tkz.GetNextToken());
	}
	
	// Check for remote user in configuration string
	if (tkz.HasMoreTokens()) {
		// Interface
		m_usernameRemote = tkz.GetNextToken();
	}
	
	// Check for remote password in configuration string
	if (tkz.HasMoreTokens()) {
		// Interface
		m_passwordRemote = tkz.GetNextToken();
	}
	
	wxString strFilter;
	// Check for filter in configuration string
	if (tkz.HasMoreTokens()) {
		// Interface
		strFilter = tkz.GetNextToken();
		vscp_readFilterFromString(&m_vscpfilter, strFilter);
	}
	
	// Check for mask in configuration string
	wxString strMask;
	if (tkz.HasMoreTokens()) {
		// Interface
		strMask = tkz.GetNextToken();
		vscp_readMaskFromString(&m_vscpfilter, strMask);
	}
	
	// First log on to the host and get configuration 
	// variables

    if ( VSCP_ERROR_SUCCESS == m_srvLocal.doCmdOpen( m_hostLocal,
								                        m_usernameLocal,
								                        m_passwordLocal ) ) {
#ifndef WIN32
		syslog(LOG_ERR,
				"%s",
				(const char *) "Unable to connect to VSCP TCP/IP interface. Terminating!");
#endif
		return false;
	}

	// Find the channel id
	uint32_t ChannelID;
	m_srvLocal.doCmdGetChannelID(&ChannelID);

	// The server should hold configuration data 
	// 
	// We look for 
	//
	//	 _host_remote		- The remote host to which we should connect
	//
	//	 _port_remote		- The port to connect to at the remote host.
	//
	//	 _user_remote		- Username to login at remote host
	//
	//	 _password_remote	- Username to login at remote host
	//
	//   _filter - Standard VSCP filter in string form. 
	//				   1,0x0000,0x0006,
	//				   ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00
	//				as priority,class,type,GUID
	//				Used to filter what events that is received from 
	//				the socketcan interface. If not give all events 
	//				are received.
	//	 _mask - Standard VSCP mask in string form.
	//				   1,0x0000,0x0006,
	//				   ff:ff:ff:ff:ff:ff:ff:01:00:00:00:00:00:00:00:00
	//				as priority,class,type,GUID
	//				Used to filter what events that is received from 
	//				the socketcan interface. If not give all events 
	//				are received. 
	//

	wxString str;
	wxString strName = m_prefix +
			wxString::FromAscii("_host_remote");
	m_srvLocal.getRemoteVariableValue(strName, m_hostRemote);
	
	strName = m_prefix +
			wxString::FromAscii("_port_remote");
	m_srvLocal.getRemoteVariableInt(strName, &m_portRemote);
	
	strName = m_prefix +
			wxString::FromAscii("_user_remote");
	m_srvLocal.getRemoteVariableValue(strName, m_usernameRemote);
	
	strName = m_prefix +
			wxString::FromAscii("_password_remote");
	m_srvLocal.getRemoteVariableValue(strName, m_passwordRemote);

	strName = m_prefix +
			wxString::FromAscii("_filter");
    if ( VSCP_ERROR_SUCCESS == m_srvLocal.getRemoteVariableValue( strName, str ) ) {
		vscp_readFilterFromString(&m_vscpfilter, str);
	}

	strName = m_prefix +
			wxString::FromAscii("_mask");
    if ( VSCP_ERROR_SUCCESS == m_srvLocal.getRemoteVariableValue( strName, str ) ) {
		vscp_readMaskFromString(&m_vscpfilter, str);
	}

	// start the workerthread
	m_pthreadSend = new CWrkSendTread();
	if (NULL != m_pthreadSend) {
		m_pthreadSend->m_pObj = this;
		m_pthreadSend->Create();
		m_pthreadSend->Run();
	} 
	else {
		rv = false;
	}
    
    // start the workerthread
	m_pthreadReceive = new CWrkReceiveTread();
	if (NULL != m_pthreadReceive) {
		m_pthreadReceive->m_pObj = this;
		m_pthreadReceive->Create();
		m_pthreadReceive->Run();
	} 
	else {
		rv = false;
	}

	// Close the channel
	m_srvLocal.doCmdClose();

	return rv;
}


//////////////////////////////////////////////////////////////////////
// close
//

void
CTcpipLink::close(void)
{
	// Do nothing if already terminated
	if (m_bQuit) return;

	m_bQuit = true; // terminate the thread
	wxSleep(1); // Give the thread some time to terminate

}


//////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//

bool 
CTcpipLink::addEvent2SendQueue(const vscpEvent *pEvent)
{
    m_mutexSendQueue.Lock();
	//m_sendQueue.Append((vscpEvent *)pEvent);
    m_sendList.push_back((vscpEvent *)pEvent);
	m_semSendQueue.Post();
	m_mutexSendQueue.Unlock();
    return true;
}

//////////////////////////////////////////////////////////////////////
//                Workerthread Send - CWrkSendTread
//////////////////////////////////////////////////////////////////////

CWrkSendTread::CWrkSendTread()
{
	m_pObj = NULL;
}

CWrkSendTread::~CWrkSendTread()
{
	;
}


//////////////////////////////////////////////////////////////////////
// Entry
//

void *
CWrkSendTread::Entry()
{
	bool bRemoteConnectionLost = false;

	::wxInitialize();
			
	// Check pointers
	if (NULL == m_pObj) return NULL;
	
	// Open remote interface
	if (m_srvRemote.doCmdOpen(m_pObj->m_hostRemote,
                                m_pObj->m_usernameRemote,
                                m_pObj->m_passwordRemote) <= 0) {
#ifndef WIN32
		syslog(LOG_ERR,
				"%s",
				(const char *) "Error while opening remote VSCP TCP/IP interface. Terminating!");
#endif
		return NULL;
	}
    
    // Find the channel id
	m_srvRemote.doCmdGetChannelID(&m_pObj->txChannelID);

	vscpEventEx eventEx;
	while (!TestDestroy() && !m_pObj->m_bQuit) {

		// Make sure the remote connection is up
		if ( !m_srvRemote.isConnected() ) {

			if (!bRemoteConnectionLost) {
				bRemoteConnectionLost = true;
				m_srvRemote.doCmdClose();
#ifndef WIN32
				syslog(LOG_ERR,
						"%s",
						(const char *) "Lost connection to remote host.");
#endif
			}

			// Wait five seconds before we try to connect again
			::wxSleep(5);

			if (m_srvRemote.doCmdOpen(m_pObj->m_hostRemote,
                                        m_pObj->m_usernameRemote,
                                        m_pObj->m_passwordRemote)) {
#ifndef WIN32
				syslog(LOG_ERR,
						"%s",
						(const char *) "Reconnected to remote host.");
#endif
                
                // Find the channel id
                m_srvRemote.doCmdGetChannelID(&m_pObj->txChannelID);
    
				bRemoteConnectionLost = false;
			}
            
            continue;

		}

        if ( wxSEMA_TIMEOUT == m_pObj->m_semSendQueue.WaitTimeout(500)) continue;
        
        // Check if there is event(s) to send
        if ( m_pObj->m_sendList.size() ) {

            // Yes there are data to send
            m_pObj->m_mutexSendQueue.Lock();
            vscpEvent *pEvent = m_pObj->m_sendList.front();
            m_pObj->m_sendList.pop_front();
            m_pObj->m_mutexSendQueue.Unlock();

            if (NULL == pEvent) continue;
			
			// Yes there are data to send
			// Send it out to the remote server
				
			m_srvRemote.doCmdSendEx(&eventEx);
			
		}
		
		
		
	}

	// Close the channel
	m_srvRemote.doCmdClose();

	return NULL;

}

//////////////////////////////////////////////////////////////////////
// OnExit
//

void
CWrkSendTread::OnExit()
{
	;
}




//////////////////////////////////////////////////////////////////////
//                Workerthread Receive - CWrkReceiveTread
//////////////////////////////////////////////////////////////////////

CWrkReceiveTread::CWrkReceiveTread()
{
	m_pObj = NULL;
}

CWrkReceiveTread::~CWrkReceiveTread()
{
	;
}


//////////////////////////////////////////////////////////////////////
// Entry
//

void *
CWrkReceiveTread::Entry()
{
	bool bRemoteConnectionLost = false;
    bool bActivity = false;

	::wxInitialize();
			
	// Check pointers
	if (NULL == m_pObj) return NULL;

	// Open remote interface
	if (m_srvRemote.doCmdOpen(m_pObj->m_hostRemote,
                                m_pObj->m_usernameRemote,
                                m_pObj->m_passwordRemote) <= 0) {
#ifndef WIN32
		syslog(LOG_ERR,
				"%s",
				(const char *) "Error while opening remote VSCP TCP/IP interface. Terminating!");
#endif
		return NULL;
	}
    
    // Enter the receive loop
    m_srvRemote.doCmdEnterReceiveLoop();

	while (!TestDestroy() && !m_pObj->m_bQuit) {

		// Make sure the remote connection is up
		if (!m_srvRemote.isConnected()) {

			if (!bRemoteConnectionLost) {
				bRemoteConnectionLost = true;
				m_srvRemote.doCmdClose();
#ifndef WIN32
				syslog(LOG_ERR,
						"%s",
						(const char *) "Lost connection to remote host.");
#endif
			}

			// Wait five seconds before we try to connect again
			::wxSleep(5);

			if (m_srvRemote.doCmdOpen(m_pObj->m_hostRemote,
                                        m_pObj->m_usernameRemote,
                                        m_pObj->m_passwordRemote)) {
#ifndef WIN32
				syslog(LOG_ERR,
						"%s",
						(const char *) "Reconnected to remote host.");
#endif
				bRemoteConnectionLost = false;
			}
            
            // Enter the receive loop
            m_srvRemote.doCmdEnterReceiveLoop();
            
            continue;

		}   
		
		// Check if remote server has something to send
        vscpEvent *pEvent = new vscpEvent;
        if (NULL != pEvent) {
            
            pEvent->sizeData = 0;
            pEvent->pdata = NULL;
            
            if (CANAL_ERROR_SUCCESS == m_srvRemote.doCmdBlockingReceive(pEvent)) {

                if ( vscp_doLevel2Filter( pEvent, 
                                        &m_pObj->m_vscpfilter) && 
                                            ( m_pObj->txChannelID != pEvent->obid ) ) {
                    m_pObj->m_mutexReceiveQueue.Lock();
                    m_pObj->m_receiveList.push_back(pEvent);
                    m_pObj->m_semReceiveQueue.Post();
                    m_pObj->m_mutexReceiveQueue.Unlock();
                }
                else {
                    vscp_deleteVSCPevent(pEvent);
                }
            }
            else {
                vscp_deleteVSCPevent(pEvent);
            }
        }
				
	}

	// Close the channel
	m_srvRemote.doCmdClose();

	return NULL;

}

//////////////////////////////////////////////////////////////////////
// OnExit
//

void
CWrkReceiveTread::OnExit()
{
	;
}


